//! What the proxy listens on and talks over: TCP on the loopbacks, for a
//! Seatbelt session, or a Unix socket, for a session with a network of its
//! own, served alike. Every server the proxy connects to is over TCP.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

/// One of a proxy's listeners.
pub enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl Listener {
    pub(super) fn accept(&self) -> io::Result<Stream> {
        Ok(match self {
            Listener::Tcp(listener) => Stream::Tcp(listener.accept()?.0),
            Listener::Unix(listener) => Stream::Unix(listener.accept()?.0),
        })
    }
}

impl From<TcpListener> for Listener {
    fn from(listener: TcpListener) -> Listener {
        Listener::Tcp(listener)
    }
}

impl From<UnixListener> for Listener {
    fn from(listener: UnixListener) -> Listener {
        Listener::Unix(listener)
    }
}

/// A connection, to a client or a server.
pub(super) enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    pub(super) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => stream.set_read_timeout(timeout),
            Stream::Unix(stream) => stream.set_read_timeout(timeout),
        }
    }

    pub(super) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => stream.set_write_timeout(timeout),
            Stream::Unix(stream) => stream.set_write_timeout(timeout),
        }
    }

    pub(super) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => stream.shutdown(how),
            Stream::Unix(stream) => stream.shutdown(how),
        }
    }

    #[cfg(test)]
    pub(super) fn try_clone(&self) -> io::Result<Stream> {
        Ok(match self {
            Stream::Tcp(stream) => Stream::Tcp(stream.try_clone()?),
            Stream::Unix(stream) => Stream::Unix(stream.try_clone()?),
        })
    }
}

impl From<TcpStream> for Stream {
    fn from(stream: TcpStream) -> Stream {
        Stream::Tcp(stream)
    }
}

impl Read for &Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => (&*stream).read(buf),
            Stream::Unix(stream) => (&*stream).read(buf),
        }
    }
}

impl Write for &Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => (&*stream).write(buf),
            Stream::Unix(stream) => (&*stream).write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => (&*stream).flush(),
            Stream::Unix(stream) => (&*stream).flush(),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self).flush()
    }
}
