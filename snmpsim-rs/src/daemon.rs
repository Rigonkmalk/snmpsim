//! Unix daemon support.
//!
//! Mirrors the Python snmpsim.daemon module.

use crate::error::{Result, SnmpsimError};

/// Daemonise the current process using the double-fork method.
///
/// Writes the PID to `pid_file` if provided.
#[cfg(unix)]
pub fn daemonize(pid_file: Option<&std::path::Path>) -> Result<()> {
    use std::fs;
    use std::io::Write;

    // First fork
    match unsafe { libc_fork() } {
        -1 => return Err(SnmpsimError::Config("fork #1 failed".into())),
        0 => {} // child continues
        _ => {
            // Parent exits
            std::process::exit(0);
        }
    }

    // Create new session
    unsafe { setsid() };

    // Second fork
    match unsafe { libc_fork() } {
        -1 => return Err(SnmpsimError::Config("fork #2 failed".into())),
        0 => {} // child continues
        _ => {
            std::process::exit(0);
        }
    }

    // Change working directory to root
    std::env::set_current_dir("/").ok();

    // Redirect stdin/stdout/stderr to /dev/null
    unsafe { redirect_stdio() };

    // Write PID file
    if let Some(pid_path) = pid_file {
        let pid = std::process::id();
        let mut f = fs::File::create(pid_path)?;
        writeln!(f, "{}", pid)?;
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn daemonize(_pid_file: Option<&std::path::Path>) -> Result<()> {
    Err(SnmpsimError::Config(
        "Daemonization is not supported on this platform".into(),
    ))
}

#[cfg(unix)]
unsafe fn libc_fork() -> i32 {
    extern "C" {
        fn fork() -> i32;
    }
    fork()
}

#[cfg(unix)]
unsafe fn setsid() -> i32 {
    extern "C" {
        fn setsid() -> i32;
    }
    setsid()
}

#[cfg(unix)]
unsafe fn redirect_stdio() {
    use std::ffi::CString;
    extern "C" {
        fn open(path: *const i8, flags: i32) -> i32;
        fn dup2(oldfd: i32, newfd: i32) -> i32;
        fn close(fd: i32) -> i32;
    }
    const O_RDONLY: i32 = 0;
    const O_WRONLY: i32 = 1;
    const O_CREAT: i32 = 64;
    const O_APPEND: i32 = 1024;

    let devnull = CString::new("/dev/null").unwrap();
    let null_r = open(devnull.as_ptr(), O_RDONLY);
    let null_w = open(devnull.as_ptr(), O_WRONLY | O_CREAT | O_APPEND);

    if null_r >= 0 {
        dup2(null_r, 0); // stdin
        close(null_r);
    }
    if null_w >= 0 {
        dup2(null_w, 1); // stdout
        dup2(null_w, 2); // stderr
        close(null_w);
    }
}

/// Drop privileges to the specified user and group.
/// If `user` or `group` is None, does nothing.
#[cfg(unix)]
pub fn drop_privileges(user: Option<&str>, group: Option<&str>) -> Result<()> {
    // Only relevant when running as root
    if !is_root() {
        return Ok(());
    }

    if user.is_none() && group.is_none() {
        return Ok(());
    }

    let user = user.ok_or_else(|| {
        SnmpsimError::Config("Must specify --process-user when dropping privileges".into())
    })?;
    let group = group.ok_or_else(|| {
        SnmpsimError::Config("Must specify --process-group when dropping privileges".into())
    })?;

    // In a real implementation this would call setgid/setuid via libc
    // For now, log a warning
    tracing::warn!(
        "Privilege dropping to {}/{} is a stub; implement via libc bindings",
        user,
        group
    );
    Ok(())
}

#[cfg(not(unix))]
pub fn drop_privileges(_user: Option<&str>, _group: Option<&str>) -> Result<()> {
    Ok(())
}

/// Return true if the current process is running as root.
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe {
            extern "C" {
                fn getuid() -> u32;
            }
            getuid() == 0
        }
    }
    #[cfg(not(unix))]
    false
}
