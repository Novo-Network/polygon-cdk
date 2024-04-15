use std::{str::FromStr, sync::Arc};

use crate::contracts::{
    polygon_zk_evm_bridge::InitializeCall, proxy_admin::TransferOwnershipCall, CDKDataCommittee,
    CDKValidium, CDKValidiumDeployer, CDKValidiumTimelock, PolygonZkEVMGlobalExitRoot,
    TransparentUpgradeableProxy, POLYGONZKEVMBRIDGE_DEPLOYED_BYTECODE,
    PROXYADMIN_DEPLOYED_BYTECODE, TRANSPARENTUPGRADEABLEPROXY_ABI,
    TRANSPARENTUPGRADEABLEPROXY_BYTECODE, TRANSPARENTUPGRADEABLEPROXY_DEPLOYED_BYTECODE,
};

use anyhow::{anyhow, Result};
use bitcoin::{hashes::Hash, Address};
use ethers::{
    abi::{AbiEncode, Token},
    contract::ContractFactory,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{Bytes, H160, U256},
    utils::{get_create2_address, hex, keccak256},
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
        let owner = Self::get_owner(btc_address)?;

        let cdkvalidium_deployer_contract = self.deploy_cdk_validium_deployer(owner).await?;
        println!(
            "CDKValidiumDeployer address:{:?}",
            cdkvalidium_deployer_contract.address()
        );

        let proxy_admin_address = self
            .deploy_proxy_admin(owner, cdkvalidium_deployer_contract.clone())
            .await?;
        println!("proxy admin address:{:?}", proxy_admin_address);

        let cdkdata_committee_address = self
            .deploy_cdkdata_committee(owner, proxy_admin_address)
            .await?;
        println!("cdk data committee address:{:?}", cdkdata_committee_address);

        let polygon_zk_evm_global_exit_root_address = self
            .deploy_polygon_zk_evm_global_exit_root(owner, proxy_admin_address)
            .await?;
        println!(
            "polygon zkevm global exit root address:{:?}",
            polygon_zk_evm_global_exit_root_address
        );

        let cdkvalidium_address = self.deploy_cdkvalidium(owner, proxy_admin_address).await?;
        println!("cdk validium address:{:?}", cdkvalidium_address);

        let polygon_zkevm_bridge_address = self
            .deploy_polygon_zk_evm_bridge(owner, proxy_admin_address, cdkvalidium_deployer_contract)
            .await?;
        println!(
            "polygon zkevm bridge address:{:?}",
            polygon_zkevm_bridge_address
        );

        let cdkvalidium_timelock_address = self.deploy_cdkvalidium_timelock(owner).await?;
        println!(
            "cdk validium timelock address:{:?}",
            cdkvalidium_timelock_address
        );

        Ok(())
    }
    fn get_owner(btc_address: &str) -> Result<H160> {
        let script = Address::from_str(btc_address)?
            .assume_checked()
            .script_pubkey();

        let hash = match script.p2pk_public_key() {
            Some(v) => keccak256(keccak256(v.to_bytes())).to_vec(),
            None => script.script_hash().as_byte_array().to_vec(),
        };
        Ok(H160::from_slice(&hash[0..20]))
    }

    async fn deploy_cdk_validium_deployer(
        &self,
        owner: H160,
    ) -> Result<Arc<CDKValidiumDeployer<SignerMiddleware<Provider<Http>, LocalWallet>>>> {
        let cdkvalidium_deployer_contract =
            CDKValidiumDeployer::deploy(self.client.clone(), owner)?
                .legacy()
                .send()
                .await?;

        Ok(Arc::new(cdkvalidium_deployer_contract))
    }

    async fn deploy_cdkdata_committee(
        &self,
        owner: H160,
        proxy_admin_address: H160,
    ) -> Result<H160> {
        let contract = CDKDataCommittee::deploy(self.client.clone(), owner)?
            .legacy()
            .send()
            .await?;
        let proxy = TransparentUpgradeableProxy::deploy(
            self.client.clone(),
            vec![
                Token::Address(contract.address()),
                Token::Address(proxy_admin_address),
                Token::Bytes(vec![]),
            ],
        )?
        .legacy()
        .send()
        .await?;

        CDKDataCommittee::new(proxy.address(), self.client.clone())
            .setup_committee(U256::zero(), Vec::new(), Bytes::new())
            .legacy()
            .send()
            .await?
            .await?;
        Ok(proxy.address())
    }

    async fn deploy_polygon_zk_evm_global_exit_root(
        &self,
        owner: H160,
        proxy_admin_address: H160,
    ) -> Result<H160> {
        let contract = PolygonZkEVMGlobalExitRoot::deploy(self.client.clone(), owner)?
            .legacy()
            .send()
            .await?;
        let proxy = TransparentUpgradeableProxy::deploy(
            self.client.clone(),
            vec![
                Token::Address(contract.address()),
                Token::Address(proxy_admin_address),
                Token::Bytes(vec![]),
            ],
        )?
        .legacy()
        .send()
        .await?;

        Ok(proxy.address())
    }

    async fn deploy_cdkvalidium(&self, owner: H160, proxy_admin_address: H160) -> Result<H160> {
        let contract = CDKValidium::deploy(self.client.clone(), owner)?
            .legacy()
            .send()
            .await?;
        let proxy = TransparentUpgradeableProxy::deploy(
            self.client.clone(),
            vec![
                Token::Address(contract.address()),
                Token::Address(proxy_admin_address),
                Token::Bytes(vec![]),
            ],
        )?
        .legacy()
        .send()
        .await?;

        Ok(proxy.address())
    }

    async fn deploy_cdkvalidium_timelock(&self, owner: H160) -> Result<H160> {
        let contract = CDKValidiumTimelock::deploy(self.client.clone(), owner)?
            .legacy()
            .send()
            .await?;

        Ok(contract.address())
    }

    async fn deploy_proxy_admin(
        &self,
        owner: H160,
        cdkvalidium_deployer_contract: Arc<
            CDKValidiumDeployer<SignerMiddleware<Provider<Http>, LocalWallet>>,
        >,
    ) -> Result<H160> {
        let address = get_create2_address(owner, &self.salt, PROXYADMIN_DEPLOYED_BYTECODE.clone());

        let call_data = TransferOwnershipCall { new_owner: owner }.encode();

        cdkvalidium_deployer_contract
            .deploy_deterministic_and_call(
                U256::zero(),
                self.salt,
                PROXYADMIN_DEPLOYED_BYTECODE.clone(),
                call_data.into(),
            )
            .legacy()
            .send()
            .await?
            .await?;
        Ok(address)
    }
    async fn deploy_polygon_zk_evm_bridge(
        &self,
        owner: H160,
        proxy_admin_address: H160,
        cdkvalidium_deployer_contract: Arc<
            CDKValidiumDeployer<SignerMiddleware<Provider<Http>, LocalWallet>>,
        >,
    ) -> Result<H160> {
        let polygon_zk_evm_bridge_address = {
            let address = get_create2_address(
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
                .legacy()
                .send()
                .await?
                .await?;
            address
        };

        let address = get_create2_address(
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

        let init_code = ContractFactory::new(
            TRANSPARENTUPGRADEABLEPROXY_ABI.clone(),
            TRANSPARENTUPGRADEABLEPROXY_BYTECODE.clone().into(),
            self.client.clone(),
        )
        .deploy(vec![
            Token::Address(polygon_zk_evm_bridge_address),
            Token::Address(proxy_admin_address),
            Token::Bytes(vec![]),
        ])?
        .tx
        .data()
        .ok_or(anyhow!("tx data not found"))?
        .clone();

        cdkvalidium_deployer_contract
            .deploy_deterministic_and_call(U256::zero(), self.salt, init_code, call_data.into())
            .legacy()
            .send()
            .await?
            .await?;

        println!("PolygonZkEVMBridge address:{:?}", address);
        Ok(address)
    }
}
