use crate::config::Configuration;
use anyhow::Result;
use enclaver::constants::TIME_VSOCK_PORT;
use enclaver::proxy::time::EnclaveTime;
use libc::{clock_settime, timespec, CLOCK_REALTIME};
use log::info;
use std::time::Duration;
use tokio::task::JoinHandle;

pub struct TimeService {
    task: JoinHandle<()>,
}

impl TimeService {
    pub async fn start(_config: &Configuration) -> Result<Self> {
        info!("Starting time");
        let task = tokio::task::spawn(async move {
            loop {
                if let Ok(date) = EnclaveTime::request(TIME_VSOCK_PORT).await {
                    // https://github.com/uutils/coreutils/blob/60fbf1db84421405c6e7c84db5489dd2b293c622/src/uu/date/src/date.rs#L433
                    let timespec = timespec {
                        tv_sec: date.timestamp() as _,
                        tv_nsec: date.timestamp_subsec_nanos() as _,
                    };
                    info!("Setting date inside enclave to {:?}", date);
                    let result = unsafe { clock_settime(CLOCK_REALTIME, &timespec) };
                    if result != 0 {
                        info!("failed to set date: {:?}", std::io::Error::last_os_error());
                    }
                }
                tokio::time::sleep(Duration::from_secs(5 * 60)).await;
            }
        });

        Ok(Self { task })
    }

    pub async fn stop(self) {
        let task = self.task;
        task.abort();
        _ = task.await;
    }
}
