use std::{
    fs::File,
    io,
    mem::MaybeUninit,
    os::{fd::FromRawFd, unix::process::CommandExt},
    process::{Child, Command, Stdio},
};

use anyhow::{Context, Result, bail};

#[derive(Clone, Copy)]
pub struct TerminalSize {
    rows: u16,
    cols: u16,
}

pub struct ChildPty {
    pub master: File,
    pub child: Child,
}

pub struct RawTerminalGuard {
    fd: libc::c_int,
    original: Option<libc::termios>,
}

impl RawTerminalGuard {
    pub fn new(fd: libc::c_int) -> Result<Self> {
        if unsafe { libc::isatty(fd) } != 1 {
            return Ok(Self { fd, original: None });
        }
        let mut original = MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error()).context("failed to read terminal mode");
        }
        let original = unsafe { original.assume_init() };
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } == -1 {
            return Err(io::Error::last_os_error()).context("failed to enable raw terminal mode");
        }
        Ok(Self {
            fd,
            original: Some(original),
        })
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, original);
            }
        }
    }
}

pub fn terminal_size(fd: libc::c_int) -> TerminalSize {
    let mut size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } == -1
        || size.ws_row == 0
        || size.ws_col == 0
    {
        return TerminalSize { rows: 24, cols: 80 };
    }
    TerminalSize {
        rows: size.ws_row,
        cols: size.ws_col,
    }
}

pub fn spawn_command(
    argv: &[std::ffi::OsString],
    env: &[(String, String)],
    size: TerminalSize,
) -> Result<ChildPty> {
    let Some(program) = argv.first() else {
        anyhow::bail!("child argv is empty");
    };
    let mut master = -1;
    let mut slave = -1;
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &winsize,
        )
    } == -1
    {
        return Err(io::Error::last_os_error()).context("failed to open PTY");
    }

    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    let stdout = slave
        .try_clone()
        .context("failed to clone PTY child stdout")?;
    let stderr = slave
        .try_clone()
        .context("failed to clone PTY child stderr")?;
    let mut command = Command::new(program);
    command
        .args(&argv[1..])
        .envs(env.iter().map(|(name, value)| (name, value)))
        .stdin(Stdio::from(slave))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().context("failed to spawn child")?;
    Ok(ChildPty { master, child })
}

pub fn resize(master_fd: libc::c_int, size: TerminalSize) {
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(master_fd, libc::TIOCSWINSZ, &winsize);
    }
}

pub fn wait_for_child(mut child: Child) -> Result<u8> {
    use std::os::unix::process::ExitStatusExt;

    let status = child.wait().context("failed waiting for child")?;
    if let Some(code) = status.code() {
        return Ok(code as u8);
    }
    if let Some(signal) = status.signal() {
        return Ok((128 + signal).min(255) as u8);
    }
    bail!("child exited with an unknown status: {status}")
}
