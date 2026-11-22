//! The TUN device (sing-tun `tun_linux.go` `open`): `/dev/net/tun` (or
//! Android's `/dev/tun`) with `IFF_TUN | IFF_NO_PI`, non-blocking, read and
//! written one IP packet at a time through tokio.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

pub struct Device {
    fd: AsyncFd<OwnedFd>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod sys {
    pub const TUNSETIFF: libc::c_ulong = 0x400454ca;
    pub const TUNGETIFF: libc::c_ulong = 0x800454d2;
    pub const IFF_TUN: libc::c_short = 0x0001;
    pub const IFF_NO_PI: libc::c_short = 0x1000;

    #[repr(C)]
    pub struct IfReq {
        pub name: [u8; libc::IFNAMSIZ],
        pub flags: libc::c_short,
        pub padding: [u8; 22],
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: the descriptor is owned by the AsyncFd and stays open as long as it.
    unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)
}

impl Device {
    /// Opens (creating it when missing) the TUN interface `name`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn open(name: &str) -> io::Result<Device> {
        if name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("interface name too long: {name}")));
        }
        let path = if std::path::Path::new("/dev/tun").exists() { "/dev/tun\0" } else { "/dev/net/tun\0" };
        // SAFETY: a NUL-terminated path.
        let raw = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR | libc::O_CLOEXEC) };
        if raw < 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(error.kind(), format!("open {}: {error}", path.trim_end_matches('\0'))));
        }
        // SAFETY: just opened, owned from here on.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut request =
            sys::IfReq { name: [0; libc::IFNAMSIZ], flags: sys::IFF_TUN | sys::IFF_NO_PI, padding: [0; 22] };
        request.name[..name.len()].copy_from_slice(name.as_bytes());
        // SAFETY: TUNSETIFF reads an ifreq.
        if unsafe { libc::ioctl(fd.as_raw_fd(), sys::TUNSETIFF as _, &mut request) } < 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(error.kind(), format!("TUNSETIFF: {error}")));
        }
        set_nonblocking(fd.as_raw_fd())?;
        Ok(Device { fd: register(fd)? })
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub fn open(_name: &str) -> io::Result<Device> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "`tun` is not supported by rust-box on this platform"))
    }

    /// Takes over a TUN file descriptor the platform opened.
    pub fn from_fd(fd: RawFd) -> io::Result<Device> {
        // SAFETY: the platform hands the descriptor over to rust-box.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        set_nonblocking(fd.as_raw_fd())?;
        Ok(Device { fd: register(fd)? })
    }

    /// The interface name (`TUNGETIFF`).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn name(&self) -> io::Result<String> {
        let mut request = sys::IfReq { name: [0; libc::IFNAMSIZ], flags: 0, padding: [0; 22] };
        // SAFETY: TUNGETIFF fills an ifreq.
        if unsafe { libc::ioctl(self.fd.get_ref().as_raw_fd(), sys::TUNGETIFF as _, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let end = request.name.iter().position(|&b| b == 0).unwrap_or(request.name.len());
        Ok(String::from_utf8_lossy(&request.name[..end]).into_owned())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub fn name(&self) -> io::Result<String> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Reads one packet.
    pub async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.fd
            .async_io(Interest::READABLE, |fd| {
                // SAFETY: reading into a buffer of the given length.
                let n = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            })
            .await
    }

    /// Writes one packet.
    pub async fn write(&self, packet: &[u8]) -> io::Result<usize> {
        self.fd
            .async_io(Interest::WRITABLE, |fd| {
                // SAFETY: writing a buffer of the given length.
                let n = unsafe { libc::write(fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            })
            .await
    }
}
