use std::pin::Pin;
use std::marker::Unpin;
use std::io::{ self, Read, Write };
use rustls::{ Session, ClientSession, ServerSession };
use futures::future::Future;
use futures::task::{ LocalWaker, Poll };
use futures::io::{ AsyncRead, AsyncWrite, Initializer };
use ::{
    TlsStream, MidHandshake,
    ConnectAsync, AcceptAsync,
    common::{ Stream, TaskStream }
};


macro_rules! a {
    ( < $r:expr ) => {
        match $r {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err))
        }
    };
}


impl<S: AsyncRead + AsyncWrite + Unpin> Future for ConnectAsync<S> {
    type Output = io::Result<TlsStream<S, ClientSession>>;

    fn poll(mut self: Pin<&mut Self>, lw: &LocalWaker) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(lw)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Future for AcceptAsync<S> {
    type Output = io::Result<TlsStream<S, ServerSession>>;

    fn poll(mut self: Pin<&mut Self>, lw: &LocalWaker) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(lw)
    }
}

impl<S, C> Future for MidHandshake<S, C>
    where S: AsyncRead + AsyncWrite + Unpin, C: Session + Unpin
{
    type Output = io::Result<TlsStream<S, C>>;

    fn poll(self: Pin<&mut Self>, lw: &LocalWaker) -> Poll<Self::Output> {
        let state = &mut Pin::get_mut(self).inner;
        let stream = state.as_mut().unwrap();

        if stream.session.is_handshaking() {
            let (io, session) = stream.get_mut();
            let mut taskio = TaskStream { io, task: lw };
            let mut stream = Stream::new(session, &mut taskio);

            match stream.complete_io() {
                Ok(_) => (),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e))
            }
        }

        Poll::Ready(Ok(state.take().unwrap()))
    }
}

impl<S, C> AsyncRead for TlsStream<S, C>
    where
        S: AsyncRead + AsyncWrite,
        C: Session
{
    unsafe fn initializer(&self) -> Initializer {
        Initializer::nop()
    }

    fn poll_read(&mut self, lw: &LocalWaker, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        if self.eof {
            return Poll::Ready(Ok(0));
        }

        let (io, session) = self.get_mut();
        let mut taskio = TaskStream { io, task: lw };
        let mut stream = Stream::new(session, &mut taskio);

        match stream.read(buf) {
            Ok(0) => { self.eof = true; Poll::Ready(Ok(0)) },
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                self.eof = true;
                self.is_shutdown = true;
                self.session.send_close_notify();
                Poll::Ready(Ok(0))
            },
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e))
        }
    }
}

impl<S, C> AsyncWrite for TlsStream<S, C>
    where
        S: AsyncRead + AsyncWrite,
        C: Session
{
    fn poll_write(&mut self, lw: &LocalWaker, buf: &[u8]) -> Poll<io::Result<usize>> {
        let (io, session) = self.get_mut();
        let mut taskio = TaskStream { io, task: lw };
        let mut stream = Stream::new(session, &mut taskio);

        a!(< stream.write(buf))
    }

    fn poll_flush(&mut self, lw: &LocalWaker) -> Poll<io::Result<()>> {
        let (io, session) = self.get_mut();
        let mut taskio = TaskStream { io, task: lw };
        let mut stream = Stream::new(session, &mut taskio);

        match stream.flush() {
            Ok(_) => (),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e))
        }

        a!(< taskio.flush())
    }

    fn poll_close(&mut self, lw: &LocalWaker) -> Poll<io::Result<()>> {
        if !self.is_shutdown {
            self.session.send_close_notify();
            self.is_shutdown = true;
        }

        let (io, session) = self.get_mut();
        let mut taskio = TaskStream { io, task: lw };

        match session.complete_io(&mut taskio) {
            Ok(_) => (),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e))
        }

        self.io.poll_close(lw)
    }
}
