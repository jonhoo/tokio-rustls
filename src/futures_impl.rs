use std::mem::PinMut;
use std::marker::Unpin;
use std::io::{ Read, Write };
use futures::future::Future;
use futures::task::{ Context, Poll };
use futures::io::{ AsyncRead, AsyncWrite };
use rustls::{ ClientSession, ServerSession };
use super::*;


impl<S> ConnectAsync<S> {
    unsafe_pinned!(inner: MidHandshake<S, ClientSession>);
}

impl<S> AcceptAsync<S> {
    unsafe_pinned!(inner: MidHandshake<S, ServerSession>);
}

impl<S, C> MidHandshake<S, C> {
    unsafe_unpinned!(inner: Option<TlsStream<S, C>>);
}

impl<S: Unpin> Unpin for ConnectAsync<S> {}
impl<S: Unpin> Unpin for AcceptAsync<S> {}
impl<S: Unpin, C: Unpin> Unpin for MidHandshake<S, C> {}

impl<S: AsyncRead + AsyncWrite> Future for ConnectAsync<S> {
    type Output = io::Result<TlsStream<S, ClientSession>>;

    fn poll(mut self: PinMut<Self>, ctx: &mut Context) -> Poll<Self::Output> {
        self.inner().poll(ctx)
    }
}

impl<S: AsyncRead + AsyncWrite> Future for AcceptAsync<S> {
    type Output = io::Result<TlsStream<S, ServerSession>>;

    fn poll(mut self: PinMut<Self>, ctx: &mut Context) -> Poll<Self::Output> {
        self.inner().poll(ctx)
    }
}

macro_rules! async {
    ( to $r:expr ) => {
        match $r {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
            Poll::Ready(Err(e)) => Err(e)
        }
    };
    ( from $r:expr ) => {
        match $r {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e))
        }
    };
}

struct TaskStream<'a, 'b: 'a, S: 'a> {
    io: &'a mut S,
    task: &'a mut Context<'b>
}

impl<'a, 'b, S> io::Read for TaskStream<'a, 'b, S>
    where S: AsyncRead + AsyncWrite
{
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        async!(to self.io.poll_read(self.task, buf))
    }
}

impl<'a, 'b, S> io::Write for TaskStream<'a, 'b, S>
    where S: AsyncRead + AsyncWrite
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        async!(to self.io.poll_write(self.task, buf))
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        async!(to self.io.poll_flush(self.task))
    }
}

impl<S, C> Future for MidHandshake<S, C>
    where S: AsyncRead + AsyncWrite, C: Session
{
    type Output = io::Result<TlsStream<S, C>>;

    fn poll(mut self: PinMut<Self>, ctx: &mut Context) -> Poll<Self::Output> {
        let state = self.inner();

        loop {
            let stream = state.as_mut().unwrap();
            if !stream.session.is_handshaking() { break };

            let (io, session) = stream.get_mut();
            let mut taskio = TaskStream { io, task: ctx };

            match session.complete_io(&mut taskio) {
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
    fn poll_read(&mut self, ctx: &mut Context, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        if self.eof {
            return Poll::Ready(Ok(0));
        }

        let (io, session) = self.get_mut();
        let mut taskio = TaskStream { io, task: ctx };
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
    fn poll_write(&mut self, ctx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let (io, session) = self.get_mut();
        let mut taskio = TaskStream { io, task: ctx };
        let mut stream = Stream::new(session, &mut taskio);

        async!(from stream.write(buf))
    }

    fn poll_flush(&mut self, ctx: &mut Context) -> Poll<io::Result<()>> {
        let (io, session) = self.get_mut();
        let mut taskio = TaskStream { io, task: ctx };
        let mut stream = Stream::new(session, &mut taskio);

        match stream.flush() {
            Ok(_) => (),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e))
        }

        async!(from taskio.flush())
    }

    fn poll_close(&mut self, ctx: &mut Context) -> Poll<io::Result<()>> {
        if !self.is_shutdown {
            self.session.send_close_notify();
            self.is_shutdown = true;
        }

        let (io, session) = self.get_mut();
        let mut taskio = TaskStream { io, task: ctx };

        match session.complete_io(&mut taskio) {
            Ok(_) => (),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e))
        }

        self.io.poll_close(ctx)
    }
}
