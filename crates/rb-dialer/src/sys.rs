//! Socket options that std, tokio and socket2 do not cover, mirroring sing
//! `common/control` (`bind_linux.go`, `mark_linux.go`, `reuse_unix.go`,
//! `frag_linux.go`, `bind_address_no_port_linux.go`, `protect_unix.go`) and
//! the `TCP_INFO` read of sing-box `common/tlsfragment/wait_linux.go`.
//!
//! The Linux implementations serve Android as well (sing-box's
//! `C.IsLinux` includes Android). Elsewhere the options that sing-box
//! reports as Linux-only are refused when the dialer or listener is built,
//! so the stubs here are never reached.

use std::io;
use std::path::Path;

pub type Fd = i32;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    const SO_BINDTOIFINDEX: libc::c_int = 62;
    const IP_BIND_ADDRESS_NO_PORT: libc::c_int = 24;
    pub const TCP_FASTOPEN: libc::c_int = 23;
    /// `IPPROTO_MPTCP`.
    pub const IPPROTO_MPTCP: libc::c_int = 262;
    const IP_MTU_DISCOVER: libc::c_int = 10;
    const IPV6_MTU_DISCOVER: libc::c_int = 23;
    const IP_PMTUDISC_DONT: libc::c_int = 0;
    const IP_PMTUDISC_DO: libc::c_int = 2;

    fn setsockopt_int(fd: Fd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
        // SAFETY: a valid pointer to a c_int and its size.
        let result = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn is_unsupported(error: &io::Error) -> bool {
        matches!(error.raw_os_error(), Some(libc::ENOPROTOOPT) | Some(libc::EINVAL))
    }

    /// `control.BindToInterface`: `SO_BINDTOIFINDEX`, falling back to
    /// `SO_BINDTODEVICE` on kernels without it.
    pub fn bind_to_interface(fd: Fd, name: &str) -> io::Result<()> {
        let c_name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: a NUL-terminated string.
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("interface {name} not found")));
        }
        match setsockopt_int(fd, libc::SOL_SOCKET, SO_BINDTOIFINDEX, index as libc::c_int) {
            Ok(()) => return Ok(()),
            Err(error) if is_unsupported(&error) => {}
            Err(error) => return Err(error),
        }
        let bytes = c_name.as_bytes_with_nul();
        // SAFETY: a pointer to the interface name and its length.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len() as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// `control.RoutingMark`.
    pub fn set_mark(fd: Fd, mark: u32) -> io::Result<()> {
        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_MARK, mark as libc::c_int)
    }

    /// `control.ReuseAddr`: `SO_REUSEADDR` and `SO_REUSEPORT`.
    pub fn set_reuse_addr(fd: Fd) -> io::Result<()> {
        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)
    }

    /// `control.BindAddressNoPort` (TCP only; unsupported kernels are ignored).
    pub fn set_bind_address_no_port(fd: Fd) -> io::Result<()> {
        match setsockopt_int(fd, libc::SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1) {
            Err(error) if is_unsupported(&error) => Ok(()),
            result => result,
        }
    }

    /// `control.EnableUDPFragment` / `DisableUDPFragment`: path MTU
    /// discovery off (the kernel fragments) or on (`DF` set).
    pub fn set_udp_fragment(fd: Fd, ipv6: bool, enable: bool) -> io::Result<()> {
        let value = if enable { IP_PMTUDISC_DONT } else { IP_PMTUDISC_DO };
        if ipv6 {
            setsockopt_int(fd, libc::IPPROTO_IPV6, IPV6_MTU_DISCOVER, value)
        } else {
            match setsockopt_int(fd, libc::IPPROTO_IP, IP_MTU_DISCOVER, value) {
                // gVisor rejects IP_PMTUDISC_DO with EOPNOTSUPP; sing ignores it.
                Err(error) if !enable && error.raw_os_error() == Some(libc::EOPNOTSUPP) => Ok(()),
                result => result,
            }
        }
    }

    /// Reads back the path MTU discovery mode (tests).
    pub fn udp_fragment_mode(fd: Fd, ipv6: bool) -> io::Result<i32> {
        let (level, name) =
            if ipv6 { (libc::IPPROTO_IPV6, IPV6_MTU_DISCOVER) } else { (libc::IPPROTO_IP, IP_MTU_DISCOVER) };
        getsockopt_int(fd, level, name)
    }

    pub fn getsockopt_int(fd: Fd, level: libc::c_int, name: libc::c_int) -> io::Result<i32> {
        let mut value: libc::c_int = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: a valid pointer to a c_int and its size.
        let result = unsafe {
            libc::getsockopt(fd, level, name, &mut value as *mut libc::c_int as *mut libc::c_void, &mut length)
        };
        if result == 0 {
            Ok(value)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// TCP keep-alive as Go's `net.KeepAliveConfig` sets it (count 9).
    pub fn set_keep_alive(fd: Fd, idle: std::time::Duration, interval: std::time::Duration) -> io::Result<()> {
        let round_up = |duration: std::time::Duration| duration.as_secs_f64().ceil().max(1.0) as libc::c_int;
        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
        setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, round_up(idle))?;
        setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, round_up(interval))?;
        setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 9)
    }

    /// TCP Fast Open on a listening socket (tfo-go uses a queue of 4096).
    pub fn set_tcp_fast_open_listener(fd: Fd) -> io::Result<()> {
        setsockopt_int(fd, libc::IPPROTO_TCP, TCP_FASTOPEN, 4096)
    }

    /// `tcpi_unacked` of `TCP_INFO`: segments sent and not yet acknowledged.
    pub fn tcp_unacked(fd: Fd) -> io::Result<u32> {
        // struct tcp_info: eight one-byte fields, then u32 rto, ato,
        // snd_mss, rcv_mss, unacked.
        let mut info = [0u8; 232];
        let mut length = info.len() as libc::socklen_t;
        // SAFETY: a buffer and its size; the kernel fills at most that much.
        let result = unsafe {
            libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, info.as_mut_ptr() as *mut libc::c_void, &mut length)
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if (length as usize) < 28 {
            return Err(io::Error::other("short TCP_INFO"));
        }
        Ok(u32::from_ne_bytes([info[24], info[25], info[26], info[27]]))
    }

    /// `control.ProtectPath`: hands the socket to a protector over a Unix
    /// socket (`SCM_RIGHTS`) and waits for its one-byte answer.
    pub fn protect(fd: Fd, path: &Path) -> io::Result<()> {
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(path)
            .map_err(|error| io::Error::new(error.kind(), format!("connect protect path: {error}")))?;
        let dummy = [1u8];
        let mut iov = libc::iovec { iov_base: dummy.as_ptr() as *mut libc::c_void, iov_len: 1 };
        // SAFETY: CMSG_SPACE is a pure size computation.
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
        let mut control = vec![0u8; space];
        // SAFETY: zero is a valid msghdr.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = space as _;
        // SAFETY: the control buffer has room for one cmsghdr carrying one fd.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(header) as *mut libc::c_int, fd);
        }
        // SAFETY: a fully initialized msghdr whose buffers outlive the call.
        let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut answer = [0u8; 1];
        if stream.read(&mut answer)? != 1 {
            return Err(io::Error::other("failed to protect fd"));
        }
        Ok(())
    }

    /// Runs `block` on a thread that entered the network namespace at
    /// `path` (sing-box `listener.ListenNetworkNamespace`). Sockets created
    /// there stay in that namespace.
    pub fn in_netns<T: Send>(path: &Path, block: impl FnOnce() -> io::Result<T> + Send) -> io::Result<T> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let file = std::fs::File::open(path).map_err(|error| {
                        io::Error::new(error.kind(), format!("get netns {}: {error}", path.display()))
                    })?;
                    // SAFETY: a valid descriptor of a namespace file.
                    if unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                        let error = io::Error::last_os_error();
                        return Err(io::Error::new(error.kind(), format!("set netns to {}: {error}", path.display())));
                    }
                    block()
                })
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("netns thread panicked")))
        })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod imp {
    use super::*;

    fn unsupported(what: &str) -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, format!("{what} is not supported by rust-box on this platform"))
    }

    pub fn bind_to_interface(_fd: Fd, _name: &str) -> io::Result<()> {
        Err(unsupported("`bind_interface`"))
    }
    pub fn set_mark(_fd: Fd, _mark: u32) -> io::Result<()> {
        Err(unsupported("`routing_mark`"))
    }
    pub fn set_reuse_addr(fd: Fd) -> io::Result<()> {
        // SAFETY: the descriptor stays owned by the caller.
        let socket =
            std::mem::ManuallyDrop::new(unsafe { <socket2::Socket as std::os::fd::FromRawFd>::from_raw_fd(fd) });
        socket.set_reuse_address(true)
    }
    pub fn set_bind_address_no_port(_fd: Fd) -> io::Result<()> {
        Err(unsupported("`bind_address_no_port`"))
    }
    /// sing's non-Linux builds leave fragmentation to the system defaults
    /// except on macOS and Windows; rust-box does the same everywhere but
    /// Linux and Android.
    pub fn set_udp_fragment(_fd: Fd, _ipv6: bool, _enable: bool) -> io::Result<()> {
        Ok(())
    }
    pub fn set_keep_alive(fd: Fd, idle: std::time::Duration, interval: std::time::Duration) -> io::Result<()> {
        let _ = interval;
        // SAFETY: the descriptor stays owned by the caller.
        let socket =
            std::mem::ManuallyDrop::new(unsafe { <socket2::Socket as std::os::fd::FromRawFd>::from_raw_fd(fd) });
        socket.set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(idle))
    }
    pub fn set_tcp_fast_open_listener(_fd: Fd) -> io::Result<()> {
        Err(unsupported("`tcp_fast_open`"))
    }
    pub fn tcp_unacked(_fd: Fd) -> io::Result<u32> {
        Err(unsupported("TCP_INFO"))
    }
    pub fn protect(_fd: Fd, _path: &Path) -> io::Result<()> {
        Err(unsupported("`protect_path`"))
    }
    pub fn in_netns<T: Send>(_path: &Path, _block: impl FnOnce() -> io::Result<T> + Send) -> io::Result<T> {
        Err(unsupported("`netns`"))
    }
}

pub use imp::*;

/// Whether this build implements the Linux-only socket options.
pub const IS_LINUX: bool = cfg!(any(target_os = "linux", target_os = "android"));

/// Runs `block` in the network namespace `netns` when one is set.
pub fn maybe_in_netns<T: Send>(netns: Option<&Path>, block: impl FnOnce() -> io::Result<T> + Send) -> io::Result<T> {
    match netns {
        Some(path) => in_netns(path, block),
        None => block(),
    }
}

/// The path of a network namespace given by name or path (vishvananda
/// `netns.GetFromName` looks names up under `/var/run/netns`).
pub fn netns_path(name_or_path: &str) -> std::path::PathBuf {
    if name_or_path.starts_with('/') {
        std::path::PathBuf::from(name_or_path)
    } else {
        Path::new("/var/run/netns").join(name_or_path)
    }
}
