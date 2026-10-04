mod api;
mod audit;
mod auto;
mod connect;
mod parser;
mod pty;
mod relay;
mod store;
mod tunnel;

use std::{
    ffi::OsString,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
    os::fd::AsRawFd,
    os::unix::fs::PermissionsExt,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Command as ProcessCommand, ExitCode},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use audit::{AuditEvent, AuditLog};
use auto::AutoApprover;
use clap::{Args, Parser, Subcommand};
use parser::{MarkerParser, StreamAction};
use rand::RngCore;
use store::{Store, validate_suggestion};
use tempfile::NamedTempFile;
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(name = "witness", version, about = "Record an interactive shell")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Wrap a shell on the session host and serve the read-only API
    Run(RunArgs),
    /// Open SSH from the session host with witness hooks on the remote shell
    Ssh {
        #[command(flatten)]
        session: SessionArgs,
        /// Arguments passed through to ssh (host and any ssh options)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        args: Vec<String>,
    },
    /// Run an untrusted WebSocket relay
    Serve {
        /// Address to bind the relay to
        #[arg(long, default_value = "0.0.0.0:8080")]
        addr: SocketAddr,
        /// Hold each agent until a human approves its channel at /admin
        #[arg(long)]
        require_approval: bool,
        /// Minutes of agent silence after which an approval lapses
        #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
        approval_idle_minutes: u64,
    },
    /// On the agent host, expose a relayed session on a local HTTP API
    Connect(ConnectArgs),
    /// Print a fresh random bearer token and exit
    Token,
    /// Print a fresh relay key and exit
    Key,
}

#[derive(Args)]
struct RunArgs {
    /// Shell to wrap
    #[arg(long, default_value = "/bin/bash")]
    shell: PathBuf,
    /// Address to bind the API to (host:port; port 0 picks a free port)
    #[arg(long)]
    addr: Option<SocketAddr>,
    /// Hostname to advertise in the banner and docs (defaults to the machine's FQDN/IP)
    #[arg(long)]
    public_host: Option<String>,
    /// Bearer token (defaults to $WITNESS_TOKEN, else a random one is generated)
    #[arg(long)]
    token: Option<String>,
    /// Maximum number of command records retained
    #[arg(long, default_value_t = 10_000)]
    max_commands: usize,
    /// Maximum captured output bytes per command
    #[arg(long, default_value_t = 1_048_576)]
    max_output_bytes: usize,
    #[command(flatten)]
    session: SessionArgs,
}

#[derive(Args)]
struct SessionArgs {
    /// Run agent suggestions as soon as the prompt is idle instead of waiting
    /// for Ctrl-G. DANGEROUS: anyone holding the token can execute commands
    #[arg(long)]
    auto_approve: bool,
    /// Append every command and suggestion to this JSON Lines audit log
    /// (always on with --auto-approve; defaults to
    /// $XDG_STATE_HOME/witness/audit.log)
    #[arg(long)]
    audit_log: Option<PathBuf>,
    /// Relay URL reachable by both the session host and agent host
    #[arg(long)]
    relay: Option<String>,
    /// Read the relay key from this file (preferred over WITNESS_RELAY_KEY)
    #[arg(long)]
    relay_key_file: Option<PathBuf>,
}

#[derive(Args)]
struct ConnectArgs {
    /// Relay URL used by the session host
    relay_url: String,
    /// Address for the local API
    #[arg(long, default_value = "127.0.0.1:0")]
    addr: SocketAddr,
    /// Local bearer token (defaults to $WITNESS_TOKEN, else a random one)
    #[arg(long)]
    token: Option<String>,
    /// Read the relay key from this file (preferred over WITNESS_RELAY_KEY)
    #[arg(long)]
    relay_key_file: Option<PathBuf>,
}

struct Config {
    addr: Option<SocketAddr>,
    public_host: Option<String>,
    token: Option<String>,
    max_commands: usize,
    max_output_bytes: usize,
    auto_approve: bool,
    audit_log: Option<PathBuf>,
    relay: Option<String>,
    relay_key_file: Option<PathBuf>,
}

/// Handles shared by the PTY reader, the stdin copier, and the API.
#[derive(Clone)]
struct Session {
    store: Arc<Mutex<Store>>,
    notifier: api::Notifier,
    audit: Option<Arc<AuditLog>>,
    auto: Option<Arc<AutoApprover>>,
}

impl Session {
    fn audit(&self, event: &AuditEvent) {
        if let Some(audit) = &self.audit {
            audit.record_or_warn(&self.notifier, event);
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            addr: None,
            public_host: None,
            token: None,
            max_commands: 10_000,
            max_output_bytes: 1_048_576,
            auto_approve: false,
            audit_log: None,
            relay: None,
            relay_key_file: None,
        }
    }
}

impl From<&RunArgs> for Config {
    fn from(args: &RunArgs) -> Self {
        Self {
            addr: args.addr,
            public_host: args.public_host.clone(),
            token: args.token.clone(),
            max_commands: args.max_commands,
            max_output_bytes: args.max_output_bytes,
            auto_approve: args.session.auto_approve,
            audit_log: args.session.audit_log.clone(),
            relay: args.session.relay.clone(),
            relay_key_file: args.session.relay_key_file.clone(),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Token => {
            println!("{}", generate_token());
            ExitCode::SUCCESS
        }
        Command::Key => {
            println!("{}", tunnel::RelayKey::generate());
            ExitCode::SUCCESS
        }
        Command::Serve {
            addr,
            require_approval,
            approval_idle_minutes,
        } => match relay::serve(
            addr,
            require_approval.then(|| Duration::from_secs(approval_idle_minutes * 60)),
        )
        .await
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("witness: {error:#}");
                ExitCode::FAILURE
            }
        },
        Command::Connect(args) => {
            match connect::run(args.relay_url, args.addr, args.token, args.relay_key_file).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("witness: {error:#}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Run(args) => match run(args).await {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("witness: {error:#}");
                ExitCode::FAILURE
            }
        },
        Command::Ssh { session, args } => match ssh(session, args).await {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("witness: {error:#}");
                ExitCode::FAILURE
            }
        },
    }
}

async fn run(args: RunArgs) -> Result<u8> {
    let mut rcfile = NamedTempFile::new().context("failed to create temporary bash rcfile")?;
    rcfile
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .context("failed to set bash rcfile permissions")?;
    rcfile
        .write_all(witness_hook_rc().as_bytes())
        .context("failed to write temporary bash rcfile")?;
    rcfile.flush().context("failed to flush bash rcfile")?;
    let child_argv = vec![
        args.shell.clone().into_os_string(),
        OsString::from("--rcfile"),
        rcfile.path().as_os_str().to_owned(),
        OsString::from("-i"),
    ];
    run_session(&child_argv, &session_child_env(), &Config::from(&args)).await
}

async fn ssh(session: SessionArgs, args: Vec<String>) -> Result<u8> {
    let child_argv = ssh_argv(args);
    if std::env::var_os("WITNESS_SESSION").is_some() {
        if session.auto_approve
            || session.audit_log.is_some()
            || session.relay.is_some()
            || session.relay_key_file.is_some()
        {
            eprintln!(
                "witness: already inside a session; --auto-approve, --audit-log, --relay, and --relay-key-file are set by the outer `witness run` and ignored here"
            );
        }
        let error = ProcessCommand::new(&child_argv[0])
            .args(&child_argv[1..])
            .exec();
        return Err(error).context("failed to exec ssh");
    }
    let cfg = Config {
        auto_approve: session.auto_approve,
        audit_log: session.audit_log,
        relay: session.relay,
        relay_key_file: session.relay_key_file,
        ..Config::default()
    };
    run_session(&child_argv, &session_child_env(), &cfg).await
}

async fn run_session(
    child_argv: &[OsString],
    child_env: &[(String, String)],
    cfg: &Config,
) -> Result<u8> {
    let relay = match cfg.relay.as_deref() {
        Some(url) => {
            let (key, supplied) = tunnel::session_key(cfg.relay_key_file.as_deref())?;
            tunnel::relay_url(url, &key, tunnel::Role::Session)?;
            Some((url.to_owned(), key, supplied))
        }
        None => None,
    };
    let token = cfg
        .token
        .clone()
        .or_else(|| std::env::var("WITNESS_TOKEN").ok())
        .unwrap_or_else(generate_token);

    let store = Arc::new(Mutex::new(Store::new(
        cfg.max_commands,
        cfg.max_output_bytes,
    )));
    let audit_path = match &cfg.audit_log {
        Some(path) => Some(path.clone()),
        None if cfg.auto_approve => Some(
            audit::default_path()
                .context("no default audit log location; pass --audit-log <path>")?,
        ),
        None => None,
    };
    let audit = audit_path
        .map(|path| AuditLog::open(&path).map(Arc::new))
        .transpose()?;
    if let Some(audit) = &audit {
        audit
            .record(&AuditEvent::SessionStarted {
                auto_approve: cfg.auto_approve,
            })
            .with_context(|| format!("failed to write audit log {}", audit.path().display()))?;
    }
    let bind_addr = cfg.addr.unwrap_or_else(|| {
        if relay.is_some() {
            SocketAddr::from(([127, 0, 0, 1], 0))
        } else {
            SocketAddr::from(([0, 0, 0, 0], 0))
        }
    });
    let listener = TcpListener::bind(bind_addr)
        .with_context(|| format!("failed to bind HTTP API to {bind_addr}"))?;
    // A loopback-only API is not reachable under the machine's public name.
    let public_host = cfg.public_host.clone().unwrap_or_else(|| {
        if bind_addr.ip().is_loopback() {
            bind_addr.ip().to_string()
        } else {
            resolve_public_host()
        }
    });
    let local_addr = listener
        .local_addr()
        .context("failed to read bound HTTP API address")?;
    listener
        .set_nonblocking(true)
        .context("failed to make HTTP API listener nonblocking")?;
    let listener = tokio::net::TcpListener::from_std(listener)
        .context("failed to initialize async HTTP API listener")?;
    let port = local_addr.port();
    let base_url = format!("http://{public_host}:{port}");

    if cfg.auto_approve {
        eprintln!(
            "witness: session ready — AUTO-APPROVE: agent suggestions run without confirmation"
        );
        eprintln!("witness: anyone holding the token below can execute commands as you");
    } else {
        eprintln!(
            "witness: session ready — observational shell view with human-approved suggestions"
        );
    }
    eprintln!("witness: api    {base_url}");
    eprintln!("witness: token  {token}");
    if let Some(audit) = &audit {
        eprintln!("witness: audit  {}", audit.path().display());
    }
    if let Some((url, key, supplied)) = &relay {
        eprintln!("witness: relay  {url}");
        if *supplied {
            eprintln!("witness: key    (supplied)");
        } else {
            eprintln!("witness: key    {key}");
        }
        eprintln!("witness:");
        eprintln!("witness: on the agent host run, then enter the key when asked:");
        eprintln!("witness:   witness connect {url}");
    }
    eprintln!("witness:");
    eprintln!("witness: give your agent this URL and say \"read this\":");
    eprintln!("witness:   {base_url}/docs.md?token={token}");

    let size = pty::terminal_size(io::stdin().as_raw_fd());
    let raw_guard = pty::RawTerminalGuard::new(io::stdin().as_raw_fd())?;
    let child = pty::spawn_command(child_argv, child_env, size)?;
    let reader = child
        .master
        .try_clone()
        .context("failed to clone PTY reader")?;
    let resize_master = child
        .master
        .try_clone()
        .context("failed to clone PTY resize handle")?;
    let writer = Arc::new(Mutex::new(child.master));
    let notifier = api::Notifier::new();
    let auto = match &audit {
        Some(audit) if cfg.auto_approve => Some(Arc::new(AutoApprover::new(
            Arc::clone(&store),
            notifier.clone(),
            Arc::clone(audit),
            Arc::clone(&writer),
        ))),
        _ => None,
    };
    let session = Session {
        store,
        notifier,
        audit,
        auto,
    };

    let tunnel_task = relay.map(|(url, key, _)| {
        let app = api::tunnel_router(
            Arc::clone(&session.store),
            session.notifier.clone(),
            session.audit.clone(),
            session.auto.clone(),
        );
        tunnel::spawn_session(url, key, app)
    });

    let reader_session = session.clone();
    let (reader_tx, reader_rx) = oneshot::channel();
    let _reader_thread = thread::spawn(move || {
        let _ = reader_tx.send(read_pty(reader, reader_session));
    });
    let input_session = session.clone();
    let _input_thread = thread::spawn(move || copy_stdin(writer, input_session));

    let resize_task = spawn_resize_task(resize_master);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let app = api::router(
        session.store,
        session.notifier,
        session.audit,
        session.auto,
        token,
        public_host,
        port,
    );
    let mut server_task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let status = tokio::task::spawn_blocking(move || pty::wait_for_child(child.child))
        .await
        .context("child wait task panicked")??;

    let _ = shutdown_tx.send(());
    resize_task.abort();
    if let Some(task) = tunnel_task {
        task.abort();
    }
    match tokio::time::timeout(Duration::from_secs(2), reader_rx).await {
        Ok(Ok(result)) => result?,
        Ok(Err(_)) => anyhow::bail!("PTY reader thread stopped unexpectedly"),
        Err(_) => {}
    }
    match tokio::time::timeout(Duration::from_secs(2), &mut server_task).await {
        Ok(result) => result
            .context("HTTP server task panicked")?
            .context("HTTP server failed")?,
        Err(_) => server_task.abort(),
    }
    drop(raw_guard);

    Ok(status)
}

fn session_child_env() -> Vec<(String, String)> {
    vec![("WITNESS_SESSION".to_owned(), "1".to_owned())]
}

fn witness_hook_rc() -> String {
    r#"export WITNESS_HOOK="${BASH_SOURCE[0]}"
export WITNESS_SESSION=1
# witness integration
if [ -f /etc/bash.bashrc ]; then source /etc/bash.bashrc; fi
if [ -f "$HOME/.bashrc" ]; then source "$HOME/.bashrc"; fi
__witness_armed=0
__witness_open=0
__witness_precmd() {
  __witness_ret=$?
  if [ "$__witness_open" = 1 ]; then
    printf '\033]1337;witness;E;%d\007' "$__witness_ret"
    __witness_open=0
  fi
  return 0
}
__witness_arm() {
  __witness_armed=1
  __witness_prev_hist="$(HISTTIMEFORMAT= builtin history 1 2>/dev/null)"
  printf '\033]1337;witness;P\007'
  case "$PS1" in
    *"(witness)"*) : ;;
    *) PS1="\[\033[1;38;5;208m\](witness)\[\033[0m\] $PS1" ;;
  esac
  return 0
}
__witness_preexec() {
  [ -n "$COMP_LINE" ] && return
  [ "$__witness_armed" = 1 ] || return
  __witness_armed=0
  __witness_open=1
  # BASH_COMMAND is only the first simple command of a compound line, so
  # prefer the full line bash just appended to history. If the history entry
  # did not change (ignorespace, history off), only trust it when it still
  # contains BASH_COMMAND (ignoredups repeat); otherwise fall back.
  local __cur __cmd __text=""
  __cmd="$BASH_COMMAND"
  __cur="$(HISTTIMEFORMAT= builtin history 1 2>/dev/null)"
  if [ -n "$__cur" ]; then
    if [[ "$__cur" =~ ^[[:space:]]*[0-9]+\*?[[:space:]]+(.*)$ ]]; then
      __text="${BASH_REMATCH[1]}"
    fi
    if [ -n "$__text" ]; then
      if [ "$__cur" != "$__witness_prev_hist" ]; then
        __cmd="$__text"
      elif [[ "$__text" == *"$BASH_COMMAND"* ]]; then
        __cmd="$__text"
      fi
    fi
  fi
  printf '\033]1337;witness;B;%s\007' "$__cmd"
}
trap '__witness_preexec' DEBUG
PROMPT_COMMAND="__witness_precmd${PROMPT_COMMAND:+;$PROMPT_COMMAND};__witness_arm"

# --- keep hooks across privilege changes into a new interactive shell ---
# trap/PROMPT_COMMAND do not survive exec into a fresh shell, so wrap sudo/su to
# relaunch an interactive bash that re-sources our hook. On ANY doubt, fall
# through to the real command so normal sudo/su usage is never altered. These are
# functions, so scripts (which do not inherit functions) call the real binaries.
sudo() {
  if [ -z "$WITNESS_HOOK" ] || ! command -v sudo >/dev/null 2>&1; then command sudo "$@"; return; fi
  local a want=0 complex=0 expect=0 found=0
  local -a rest=()
  for a in "$@"; do
    if [ "$found" = 1 ]; then rest+=("$a"); continue; fi
    if [ "$expect" = 1 ]; then expect=0; continue; fi
    case "$a" in
      -i|--login|-s|--shell) want=1 ;;
      -H|-E|-k|-K|-n|-b|-S|-A|-P|--) : ;;
      -u|--user|-g|--group|-C|--close-from|-c|-p|--prompt|-r|--role|-t|--type|-T|--command-timeout|-R|--chroot|-h|--host|-D|-U) complex=1; expect=1 ;;
      -*) complex=1 ;;
      *) found=1; rest=("$a") ;;
    esac
  done
  if [ "$complex" = 0 ]; then
    if [ "${#rest[@]}" = 0 ] && [ "$want" = 1 ]; then
      command sudo -H bash --rcfile "$WITNESS_HOOK" -i; return
    fi
    case "${rest[0]:-}" in
      bash|sh|zsh)
        if [ "${#rest[@]}" = 1 ]; then command sudo -H bash --rcfile "$WITNESS_HOOK" -i; return; fi ;;
      su)
        local ok=1 x
        for x in "${rest[@]:1}"; do
          case "$x" in
            -|-l|--login|-s|--shell|-m|-p|--preserve-environment) : ;;
            *) ok=0 ;;
          esac
        done
        [ "$ok" = 1 ] && { command sudo -H bash --rcfile "$WITNESS_HOOK" -i; return; } ;;
    esac
  fi
  command sudo "$@"
}
su() {
  if [ -z "$WITNESS_HOOK" ]; then command su "$@"; return; fi
  local a user="" login="" bail=0
  for a in "$@"; do
    case "$a" in
      -|-l|--login) login="-" ;;
      -m|-p|--preserve-environment|-s|--shell) : ;;
      -c|--command|--session-command) bail=1 ;;
      -*) bail=1 ;;
      *) if [ -z "$user" ]; then user="$a"; else bail=1; fi ;;
    esac
  done
  if [ "$bail" = 0 ]; then
    command su ${login:+-} ${user:+"$user"} -c "exec bash --rcfile $WITNESS_HOOK -i"
    return
  fi
  command su "$@"
}
"#
    .to_owned()
}

fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let bits = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(ALPHABET[((bits >> 18) & 0x3f) as usize] as char);
        output.push(ALPHABET[((bits >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[((bits >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[(bits & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn remote_bootstrap() -> String {
    let encoded = base64_encode(witness_hook_rc().as_bytes());
    // Create the remote hook with mktemp (secure O_EXCL creation, unpredictable
    // name, 0600) rather than a predictable /tmp path, avoiding symlink/TOCTOU
    // attacks in the world-writable temp directory. The hook self-locates its own
    // path via ${BASH_SOURCE[0]}, so nothing needs to be embedded here.
    format!(
        "__W=\"$(mktemp)\" && chmod 600 \"$__W\" && printf %s '{encoded}' | base64 -d > \"$__W\" && bash --rcfile \"$__W\" -i; rm -f \"$__W\""
    )
}

fn ssh_argv(args: Vec<String>) -> Vec<OsString> {
    let mut argv = Vec::with_capacity(args.len() + 3);
    argv.push(OsString::from("ssh"));
    argv.push(OsString::from("-t"));
    argv.extend(args.into_iter().map(OsString::from));
    argv.push(OsString::from(remote_bootstrap()));
    argv
}

fn read_pty(mut reader: std::fs::File, session: Session) -> Result<()> {
    let mut parser = MarkerParser::new();
    let mut buffer = [0_u8; 8192];

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let parsed = parser.feed(&buffer[..count]);
                session
                    .notifier
                    .write(&parsed.cleaned)
                    .context("failed to write shell output")?;
                apply_actions(&session, parsed.actions)?;
            }
            Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("failed to read PTY"),
        }
    }

    let parsed = parser.finish();
    session
        .notifier
        .write(&parsed.cleaned)
        .context("failed to write final shell output")?;
    apply_actions(&session, parsed.actions)?;
    finish_command(&session, None);
    Ok(())
}

fn finish_command(session: &Session, exit_code: Option<i32>) {
    let finished = session.store.lock().unwrap().finish_open(exit_code);
    if let Some(command_id) = finished {
        session.audit(&AuditEvent::CommandFinished {
            command_id,
            exit_code,
        });
    }
}

fn apply_actions(session: &Session, actions: Vec<StreamAction>) -> Result<()> {
    for action in actions {
        match action {
            StreamAction::Output(bytes, true) => {
                session.store.lock().unwrap().append_output(&bytes)
            }
            StreamAction::Output(_, false) => {}
            StreamAction::Event(parser::ParseEvent::Begin(command)) => {
                finish_command(session, None);
                let command_id = session.store.lock().unwrap().begin(command.clone());
                session.audit(&AuditEvent::CommandStarted {
                    command_id,
                    command: &command,
                });
            }
            StreamAction::Event(parser::ParseEvent::End(code)) => {
                finish_command(session, Some(code));
                let notices = session.store.lock().unwrap().take_pending_notices();
                for notice in notices {
                    session
                        .notifier
                        .write(notice.as_bytes())
                        .context("failed to write suggestion notice")?;
                }
            }
            StreamAction::Event(parser::ParseEvent::Prompt) => {
                session.store.lock().unwrap().prompt_shown();
                if let Some(auto) = &session.auto {
                    auto.dispatch_next();
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum InputAction {
    Forward(Vec<u8>),
    InsertSuggestion,
}

struct InputFilter;

impl InputFilter {
    fn feed(&mut self, chunk: &[u8]) -> Vec<InputAction> {
        let mut actions = Vec::new();
        let mut start = 0;
        for (index, byte) in chunk.iter().enumerate() {
            if *byte != 0x07 {
                continue;
            }
            if start < index {
                actions.push(InputAction::Forward(chunk[start..index].to_vec()));
            }
            actions.push(InputAction::InsertSuggestion);
            start = index + 1;
        }
        if start < chunk.len() {
            actions.push(InputAction::Forward(chunk[start..].to_vec()));
        }
        actions
    }
}

fn copy_stdin(writer: Arc<Mutex<std::fs::File>>, session: Session) {
    let mut stdin = io::stdin().lock();
    let mut buffer = [0_u8; 8192];
    let mut filter = InputFilter;
    loop {
        match stdin.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let mut writer = writer.lock().unwrap();
                // Anything typed makes the prompt the human's: auto-approved
                // suggestions wait for the next fresh one.
                session.store.lock().unwrap().note_input(&buffer[..count]);
                for action in filter.feed(&buffer[..count]) {
                    let result = match action {
                        InputAction::Forward(bytes) => writer.write_all(&bytes),
                        InputAction::InsertSuggestion => {
                            let suggestion = session.store.lock().unwrap().pop_pending_suggestion();
                            if let Some(suggestion) = suggestion
                                && validate_suggestion(&suggestion.command).is_ok()
                            {
                                session.audit(&AuditEvent::Inserted {
                                    suggestion_id: suggestion.id,
                                    command: &suggestion.command,
                                });
                                writer.write_all(suggestion.command.as_bytes())
                            } else {
                                Ok(())
                            }
                        }
                    };
                    if result.is_err() {
                        return;
                    }
                }
                if writer.flush().is_err() {
                    break;
                }
                drop(writer);
                // A prompt that appeared while the writer was held could not
                // dispatch; pick it up now.
                if let Some(auto) = &session.auto {
                    auto.dispatch_next();
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

fn spawn_resize_task(master: std::fs::File) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        else {
            return;
        };
        while signal.recv().await.is_some() {
            let size = pty::terminal_size(io::stdin().as_raw_fd());
            pty::resize(master.as_raw_fd(), size);
        }
    })
}

pub(crate) fn generate_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let mut token = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(token, "{byte:02x}").unwrap();
    }
    token
}

fn resolve_public_host() -> String {
    // Prefer a real FQDN (one with a dot); a bare short name like "foo" is not
    // resolvable from another machine.
    if let Some(h) = hostname(&["-f"]).filter(|h| looks_like_fqdn(h)) {
        return h;
    }
    if let Some(h) = hostname(&[]).filter(|h| looks_like_fqdn(h)) {
        return h;
    }
    // Otherwise try to learn the FQDN from local DNS via a reverse lookup of the
    // primary IP; if that has no PTR record, advertise the reachable IP itself.
    if let Some(ip) = primary_ipv4() {
        if let Some(h) = reverse_dns(ip).filter(|h| looks_like_fqdn(h)) {
            return h;
        }
        return ip.to_string();
    }
    hostname(&["-f"])
        .or_else(|| hostname(&[]))
        .unwrap_or_else(|| "127.0.0.1".to_owned())
}

fn looks_like_fqdn(host: &str) -> bool {
    if !host.contains('.') || host.ends_with('.') {
        return false;
    }
    let first = host.split('.').next().unwrap_or("");
    !first.eq_ignore_ascii_case("localhost") && !first.eq_ignore_ascii_case("ip6-localhost")
}

fn hostname(args: &[&str]) -> Option<String> {
    let output = ProcessCommand::new("hostname").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let hostname = String::from_utf8(output.stdout).ok()?;
    let hostname = hostname.trim();
    if hostname.is_empty() || matches!(hostname, "localhost" | "localhost.localdomain") {
        None
    } else {
        Some(hostname.to_owned())
    }
}

/// Source IPv4 of the interface that carries the default route. We find the
/// default gateway from the routing table and ask the kernel which local
/// address it would use to reach it; if there is no gateway, fall back to
/// letting the kernel pick a source toward a public address.
fn primary_ipv4() -> Option<Ipv4Addr> {
    if let Some(ip) = default_gateway_ipv4().and_then(source_ip_toward) {
        return Some(ip);
    }
    source_ip_toward(Ipv4Addr::new(8, 8, 8, 8))
}

fn source_ip_toward(dest: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((dest, 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
        _ => None,
    }
}

fn default_gateway_ipv4() -> Option<Ipv4Addr> {
    let route = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_default_gateway(&route)
}

/// Parse the IPv4 default gateway from the contents of /proc/net/route,
/// choosing the default route (destination 0.0.0.0) with the lowest metric.
fn parse_default_gateway(route: &str) -> Option<Ipv4Addr> {
    let mut best: Option<(u32, Ipv4Addr)> = None;
    for line in route.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let _iface = fields.next()?;
        let destination = fields.next()?;
        let gateway = fields.next()?;
        let _flags = fields.next()?;
        let _refcnt = fields.next()?;
        let _use = fields.next()?;
        let metric = fields.next().unwrap_or("0");
        if destination != "00000000" {
            continue;
        }
        let Ok(raw) = u32::from_str_radix(gateway, 16) else {
            continue;
        };
        if raw == 0 {
            continue;
        }
        // /proc/net/route stores the address little-endian.
        let ip = Ipv4Addr::from(raw.to_le_bytes());
        let m = metric.parse::<u32>().unwrap_or(u32::MAX);
        if best.is_none_or(|(bm, _)| m < bm) {
            best = Some((m, ip));
        }
    }
    best.map(|(_, ip)| ip)
}

/// Reverse-resolve an IPv4 address to a hostname via local DNS, bounded by a
/// short timeout so a slow or unreachable resolver cannot stall startup.
fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(reverse_dns_blocking(ip));
    });
    rx.recv_timeout(Duration::from_millis(1500)).ok().flatten()
}

fn reverse_dns_blocking(ip: Ipv4Addr) -> Option<String> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(ip.octets()),
    };
    let mut host = [0 as libc::c_char; 256];
    let ret = unsafe {
        libc::getnameinfo(
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if ret != 0 {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
    name.to_str().ok().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{
        Cli, Command, InputAction, InputFilter, base64_encode, looks_like_fqdn, remote_bootstrap,
        witness_hook_rc,
    };

    #[test]
    fn input_filter_forwards_plain_chunk_unchanged() {
        let input = b"hello\x1b[A";
        assert_eq!(
            InputFilter.feed(input),
            vec![InputAction::Forward(input.to_vec())]
        );
    }

    #[test]
    fn input_filter_splits_around_ctrl_g() {
        assert_eq!(
            InputFilter.feed(b"before\x07after"),
            vec![
                InputAction::Forward(b"before".to_vec()),
                InputAction::InsertSuggestion,
                InputAction::Forward(b"after".to_vec()),
            ]
        );
    }

    #[test]
    fn input_filter_swallows_lone_ctrl_g() {
        assert_eq!(
            InputFilter.feed(b"\x07"),
            vec![InputAction::InsertSuggestion]
        );
    }

    #[test]
    fn input_filter_preserves_multiple_ctrl_g_actions_in_order() {
        assert_eq!(
            InputFilter.feed(b"a\x07\x07b\x07"),
            vec![
                InputAction::Forward(b"a".to_vec()),
                InputAction::InsertSuggestion,
                InputAction::InsertSuggestion,
                InputAction::Forward(b"b".to_vec()),
                InputAction::InsertSuggestion,
            ]
        );
    }

    #[test]
    fn ssh_takes_witness_flags_before_the_host_and_passes_the_rest_through() {
        let cli = Cli::parse_from(["witness", "ssh", "--auto-approve", "-p", "2222", "host"]);
        let Command::Ssh { session, args } = cli.command else {
            panic!("expected ssh");
        };
        assert!(session.auto_approve);
        assert_eq!(args, ["-p", "2222", "host"]);

        let cli = Cli::parse_from(["witness", "ssh", "host", "--auto-approve"]);
        let Command::Ssh { session, args } = cli.command else {
            panic!("expected ssh");
        };
        assert!(!session.auto_approve);
        assert_eq!(args, ["host", "--auto-approve"]);
    }

    #[test]
    fn ssh_takes_relay_before_host_without_consuming_host() {
        let cli = Cli::parse_from(["witness", "ssh", "--relay", "https://r.example", "host"]);
        let Command::Ssh { session, args } = cli.command else {
            panic!("expected ssh");
        };
        assert_eq!(session.relay.as_deref(), Some("https://r.example"));
        assert_eq!(args, ["host"]);
    }

    #[test]
    fn fqdn_requires_a_dot() {
        assert!(looks_like_fqdn("foo.example.com"));
        assert!(!looks_like_fqdn("foo"));
        assert!(!looks_like_fqdn("host."));
    }

    #[test]
    fn fqdn_rejects_localhost_labels() {
        assert!(!looks_like_fqdn("localhost.lan.example.net"));
        assert!(!looks_like_fqdn("localhost"));
        assert!(!looks_like_fqdn("ip6-localhost.example.com"));
        assert!(looks_like_fqdn("host.localhost.example.com"));
    }

    #[test]
    fn parses_default_gateway_from_proc_route() {
        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             enp5s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
             enp5s0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(
            super::parse_default_gateway(route),
            Some(std::net::Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn no_default_gateway_when_absent() {
        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             enp5s0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(super::parse_default_gateway(route), None);
    }

    #[test]
    fn base64_encodes_empty_input() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn base64_encodes_witness() {
        assert_eq!(base64_encode(b"witness"), "d2l0bmVzcw==");
    }

    #[test]
    fn base64_encodes_two_byte_tail() {
        assert_eq!(base64_encode(b"hi"), "aGk=");
    }

    #[test]
    fn hook_contains_command_lifecycle_functions() {
        let hook = witness_hook_rc();
        for expected in [
            "__witness_arm",
            "__witness_precmd",
            "trap '__witness_preexec' DEBUG",
            "PROMPT_COMMAND=",
        ] {
            assert!(hook.contains(expected), "hook is missing {expected}");
        }
    }

    #[test]
    fn hook_contains_privilege_change_wrappers() {
        let hook = witness_hook_rc();
        for expected in [
            "export WITNESS_HOOK=\"${BASH_SOURCE[0]}\"",
            "sudo()",
            "su()",
            "--rcfile \"$WITNESS_HOOK\"",
        ] {
            assert!(hook.contains(expected), "hook is missing {expected}");
        }
    }

    #[test]
    fn remote_bootstrap_uses_mktemp_not_predictable_path() {
        let bootstrap = remote_bootstrap();
        assert!(bootstrap.contains("mktemp"), "bootstrap should use mktemp");
        assert!(
            !bootstrap.contains("/tmp/.witness-hook"),
            "bootstrap must not write to a predictable path"
        );
        assert!(
            bootstrap.contains("chmod 600"),
            "bootstrap should chmod 600"
        );
    }
}
