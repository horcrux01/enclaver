use anyhow::Result;
use rtnetlink::LinkHandle;
use log::info;

use crate::nsm::Nsm;

const DEV_RANDOM: &str = "/dev/random";

pub async fn bootstrap() -> Result<()> {
    info!("Bringing up loopback interface");
    lo_up().await?;

    info!("Seeding {} with entropy from nsm device", DEV_RANDOM);
    seed_rng()?;

    Ok(())
}

async fn lo_up() -> Result<()> {
    let (conn, handle, _receiver) = rtnetlink::new_connection()?;

    // this starts the background task of reading from the rtnetlink socket
    let conn_task = tokio::spawn(conn);

    // Assume that lo interface is one and only
    let result = LinkHandle::new(handle)
        .set(1)
        .up()
        .execute()
        .await;

    // cancel the socket reading
    conn_task.abort();
    _ = conn_task.await;

    Ok(result?)
}


fn seed_rng() -> Result<()> {
    let nsm = Nsm::new();
    let seed = nsm.get_random()?;
    std::fs::write(&DEV_RANDOM, seed)?;
    Ok(())
}
