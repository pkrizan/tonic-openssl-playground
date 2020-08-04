use async_stream::try_stream;
use futures::{Stream, TryStream, TryStreamExt};
use openssl::ssl::SslAcceptor;
use std::{
    fmt::Debug,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tonic::transport::{server::Connected, Certificate};


pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;


pub const ALPN_H2_WIRE: &[u8] = b"\x02h2";


pub fn incoming<S>(
    incoming: S,
    acceptor: SslAcceptor,
) -> impl Stream<Item = Result<SslStream<S::Ok>, Error>>
where
    S: TryStream + Unpin,
    S::Ok: AsyncRead + AsyncWrite + Send + Sync + Debug + Unpin + 'static,
    S::Error: Into<crate::Error>,
{
    let mut incoming = incoming;

    try_stream! {
        while let Some(stream) = incoming.try_next().await? {
            let tls = tokio_openssl::accept(&acceptor, stream).await?;

            let ssl = SslStream {
                inner: tls
            };

            yield ssl;
        }
    }
}

#[derive(Debug)]
pub struct SslStream<S> {
    inner: tokio_openssl::SslStream<S>,
}

impl<S: Connected> Connected for SslStream<S> {
    fn remote_addr(&self) -> Option<SocketAddr> {
        let tcp = self.inner.get_ref();
        tcp.remote_addr()
    }

    fn peer_certs(&self) -> Option<Vec<Certificate>> {
        let ssl = self.inner.ssl();
        let certs = ssl.verified_chain()?;

        let certs = certs
            .iter()
            .filter_map(|c| c.to_pem().ok())
            .map(Certificate::from_pem)
            .collect();

        Some(certs)
    }
}

impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
