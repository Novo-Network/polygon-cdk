use std::{str::FromStr, sync::Arc};

use crate::contracts::{
    proxy_admin::TransferOwnershipCall, CDKValidiumDeployer, InitializeCall,
    POLYGONZKEVMBRIDGE_DEPLOYED_BYTECODE, PROXYADMIN_DEPLOYED_BYTECODE,
    TRANSPARENTUPGRADEABLEPROXY_DEPLOYED_BYTECODE,
};

use anyhow::{anyhow, Result};
use bitcoin::{hashes::Hash, Address};
use ethers::{
    abi::AbiEncode,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{H160, U256},
    utils::{hex, keccak256},
};

pub struct Deploy {
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    salt: [u8; 32],
}

impl Deploy {
    pub async fn new(rpc: &str, sk: &str, salt: &str) -> Result<Self> {
        let wallet = LocalWallet::from_bytes(&hex::decode(sk.strip_prefix("0x").unwrap_or(&sk))?)?;
        let provider = Provider::<Http>::try_from(rpc)?;

        let client = Arc::new(SignerMiddleware::new(
            provider.clone(),
            wallet.with_chain_id(provider.get_chainid().await?.as_u64()),
        ));
        let salt = hex::decode(salt.strip_prefix("0x").unwrap_or(salt))?
            .try_into()
            .map_err(|_| anyhow!("salt format error"))?;

        Ok(Self { client, salt })
    }

    pub async fn run(&self, btc_address: &str) -> Result<()> {
        let owner = {
            let script = Address::from_str(btc_address)?
                .assume_checked()
                .script_pubkey();

            let hash = match script.p2pk_public_key() {
                Some(v) => keccak256(keccak256(v.to_bytes())).to_vec(),
                None => script.script_hash().as_byte_array().to_vec(),
            };
            H160::from_slice(&hash[0..20])
        };
        let cdkvalidium_deployer_contract =
            CDKValidiumDeployer::deploy(self.client.clone(), owner)?
                .legacy()
                .send()
                .await?;
        println!(
            "CDKValidiumDeployer address:{:?}",
            cdkvalidium_deployer_contract.address()
        );
        {
            let address = ethers::utils::get_create2_address(
                owner,
                &self.salt,
                PROXYADMIN_DEPLOYED_BYTECODE.clone(),
            );

            let call_data = TransferOwnershipCall { new_owner: owner }.encode();

            cdkvalidium_deployer_contract
                .deploy_deterministic_and_call(
                    U256::zero(),
                    self.salt,
                    PROXYADMIN_DEPLOYED_BYTECODE.clone(),
                    call_data.into(),
                )
                .send()
                .await?
                .await?;
            println!("ProxyAdmin address:{:?}", address);
        }

        {
            let address = ethers::utils::get_create2_address(
                owner,
                &self.salt,
                POLYGONZKEVMBRIDGE_DEPLOYED_BYTECODE.clone(),
            );
            cdkvalidium_deployer_contract
                .deploy_deterministic(
                    U256::zero(),
                    self.salt,
                    POLYGONZKEVMBRIDGE_DEPLOYED_BYTECODE.clone(),
                )
                .send()
                .await?
                .await?;
            println!("PolygonZkEVMBridge address:{:?}", address);
        }

        {
            let address = ethers::utils::get_create2_address(
                owner,
                &self.salt,
                TRANSPARENTUPGRADEABLEPROXY_DEPLOYED_BYTECODE.clone(),
            );
            let call_data = InitializeCall {
                network_id: 0,
                global_exit_root_manager: H160::zero(),
                polygon_zk_ev_maddress: H160::zero(),
            }
            .encode();

            cdkvalidium_deployer_contract
                .deploy_deterministic_and_call(
                    U256::zero(),
                    self.salt,
                    TRANSPARENTUPGRADEABLEPROXY_DEPLOYED_BYTECODE.clone(),
                    call_data.into(),
                )
                .send()
                .await?
                .await?;

            println!("TransparentUpgradeableProxy address:{:?}", address);
        }

        Ok(())
    }
}
