use crate::proxy::egress_http::JsonTransport;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use futures::{Stream, StreamExt};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use tokio_vsock::VsockStream;

#[derive(Serialize, Deserialize)]
struct TimeRequest();

#[derive(Serialize, Deserialize)]
enum TimeResponse {
    Ok(DateTime<Utc>),
    Err(String),
}

pub struct EnclaveTime {}
impl EnclaveTime {
    pub async fn request(egress_port: u32) -> anyhow::Result<DateTime<Utc>> {
        let mut vsock = VsockStream::connect(crate::vsock::VMADDR_CID_HOST, egress_port).await?;
        debug!(
            "Connected to vsock {}:{}, sending time request",
            crate::vsock::VMADDR_CID_HOST,
            egress_port
        );

        TimeRequest().send(&mut vsock).await?;
        debug!("Sent time request");

        match TimeResponse::recv(&mut vsock).await? {
            TimeResponse::Ok(dt) => Ok(dt),
            TimeResponse::Err(e) => Err(anyhow!("Failure: {}", e)),
        }
    }
}

pub struct HostTime {
    incoming: Box<dyn Stream<Item = VsockStream> + Unpin + Send>,
}
impl HostTime {
    pub fn bind(egress_port: u32) -> anyhow::Result<Self> {
        Ok(Self {
            incoming: Box::new(crate::vsock::serve(egress_port)?),
        })
    }
    pub async fn serve(self) {
        let mut incoming = Box::into_pin(self.incoming);

        while let Some(stream) = incoming.next().await {
            tokio::task::spawn(async move {
                if let Err(err) = HostTime::service_conn(stream).await {
                    error!("{err}");
                }
            });
        }
    }
    async fn service_conn(mut vsock: VsockStream) -> anyhow::Result<()> {
        let _ = TimeRequest::recv(&mut vsock).await?;
        use rsntp::AsyncSntpClient;
        let client = AsyncSntpClient::new();
        info!("Querying time in host");
        let resp = match client.synchronize("time.aws.com").await {
            Ok(result) => match result.datetime().into_chrono_datetime() {
                Ok(date) => TimeResponse::Ok(date),
                Err(e) => TimeResponse::Err(format!("Failed to convert response: {:?}", e)),
            },
            Err(e) => TimeResponse::Err(format!("Failed to get response: {:?}", e)),
        };
        resp.send(&mut vsock).await?;
        Ok(())
    }
}
