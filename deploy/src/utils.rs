use std::{sync::Arc, thread::sleep, time::Duration};

use anyhow::{anyhow, Result};
use ethers::{
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::LocalWallet,
    types::{
        transaction::eip2718::TypedTransaction, TransactionReceipt, TransactionRequest, H160, H256,
        U256,
    },
};

pub async fn send_transaction(
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    code: Vec<u8>,
    to: Option<H160>,
    value: U256,
) -> Result<H256> {
    let mut tx = TransactionRequest::new()
        .data(code)
        .gas(U256::max_value())
        .value(value);
    if let Some(to) = to {
        tx = tx.to(to);
    }
    let mut tx = TypedTransaction::Legacy(tx);

    client.fill_transaction(&mut tx, None).await?;

    let transaction_hash = client.send_transaction(tx, None).await?.tx_hash();
    log::info!("transaction hash:{:?}", transaction_hash);
    Ok(transaction_hash)
}

pub async fn wait_transaction(
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    transaction_hash: H256,
) -> Result<()> {
    loop {
        sleep(Duration::from_secs(1));
        let transaction = client.get_transaction(transaction_hash).await?;
        if transaction.is_some() {
            return Ok(());
        }
    }
}

pub async fn get_transaction_receipt(
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    transaction_hash: H256,
) -> Result<TransactionReceipt> {
    client
        .get_transaction_receipt(transaction_hash)
        .await?
        .ok_or(anyhow!("transaction receipt not found"))
}
