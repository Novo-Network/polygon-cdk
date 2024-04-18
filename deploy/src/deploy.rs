use std::{str::FromStr, sync::Arc};

use crate::{
    contracts::{
        polygon_zk_evm_bridge, proxy_admin::TransferOwnershipCall, DeployDeterministicAndCallCall,
        DeployDeterministicCall, NewDeterministicDeploymentFilter, SetupCommitteeCall,
        CDKDATACOMMITTEE_BYTECODE, CDKVALIDIUMDEPLOYER_BYTECODE, CDKVALIDIUM_BYTECODE,
        POLYGONZKEVMBRIDGE_BYTECODE, POLYGONZKEVMGLOBALEXITROOT_BYTECODE, PROXYADMIN_BYTECODE,
        TRANSPARENTUPGRADEABLEPROXY_BYTECODE,
    },
    utils::{get_transaction_receipt, send_transaction, wait_transaction},
};

use anyhow::{anyhow, Result};
use bitcoin::{hashes::Hash, Address};
use ethers::{
    abi::{encode, AbiEncode, RawLog, Token},
    contract::EthLogDecode,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{Bytes, H160, U256, U64},
    utils::{hex, keccak256},
};

pub struct Deploy {
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    salt: [u8; 32],
    chain_id: u64,
    fork_id: u64,
    min_delay: u64,
    timelock_address: H160,
}

impl Deploy {
    pub async fn new(
        rpc: &str,
        sk: &str,
        salt: &str,
        chain_id: u64,
        fork_id: u64,
        min_delay: u64,
        timelock_address: H160,
    ) -> Result<Self> {
        let wallet = LocalWallet::from_bytes(&hex::decode(sk.strip_prefix("0x").unwrap_or(sk))?)?;
        let provider = Provider::<Http>::try_from(rpc)?;

        let client = Arc::new(SignerMiddleware::new(
            provider.clone(),
            wallet.with_chain_id(provider.get_chainid().await?.as_u64()),
        ));
        let salt = hex::decode(salt.strip_prefix("0x").unwrap_or(salt))?
            .try_into()
            .map_err(|_| anyhow!("salt format error"))?;

        Ok(Self {
            client,
            salt,
            chain_id,
            fork_id,
            min_delay,
            timelock_address,
        })
    }

    pub async fn run(&self, btc_address: &str) -> Result<()> {
        let owner = Self::get_owner(btc_address)?;
        println!("owner address:{:?}", owner);

        let cdkvalidium_deployer_address = self.deploy_cdk_validium_deployer(owner).await?;
        println!(
            "CDKValidiumDeployer address:{:?}",
            cdkvalidium_deployer_address
        );

        let proxy_admin_address = self
            .deploy_proxy_admin(owner, cdkvalidium_deployer_address)
            .await?;
        println!("ProxyAdmin address:{:?}", proxy_admin_address);

        let polygon_zkevm_bridge_address = self
            .deploy_polygon_zkevm_bridge(proxy_admin_address, cdkvalidium_deployer_address)
            .await?;
        println!(
            "PolygonZkEVMBridge address:{:?}",
            polygon_zkevm_bridge_address
        );

        let cdkdata_committee_address = self.deploy_cdk_data_committee(proxy_admin_address).await?;
        println!("CDKDataCommittee address:{:?}", cdkdata_committee_address);

        let rollup_address = {
            let nonce = self.client.get_transaction_count(owner, None).await?;
            ethers::utils::get_contract_address(owner, nonce + U256::zero())
        };
        let polygon_zk_evm_global_exit_root_address = self
            .deploy_polygon_zkevm_global_exit_root(
                proxy_admin_address,
                rollup_address,
                polygon_zkevm_bridge_address,
            )
            .await?;
        println!(
            "PolygonZkEVMGlobalExitRoot address:{:?}",
            polygon_zk_evm_global_exit_root_address
        );

        let cdkvalidium_address = self
            .deploy_cdkvalidium(
                proxy_admin_address,
                polygon_zk_evm_global_exit_root_address,
                H160::default(),
                H160::default(),
                polygon_zkevm_bridge_address,
                cdkdata_committee_address,
            )
            .await?;
        println!("cdk validium address:{:?}", cdkvalidium_address);

        self.init_polygon_zkevm_bridge(
            polygon_zkevm_bridge_address,
            polygon_zk_evm_global_exit_root_address,
            cdkvalidium_address,
        )
        .await?;

        let cdkvalidium_timelock_address = self
            .deploy_cdkvalidium_timelock(cdkvalidium_address)
            .await?;
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

    async fn deploy_cdk_validium_deployer(&self, owner: H160) -> Result<H160> {
        let data = CDKVALIDIUMDEPLOYER_BYTECODE
            .clone()
            .into_iter()
            .chain(encode(&[Token::Address(owner)]))
            .collect::<Vec<_>>();

        let transaction_hash =
            send_transaction(self.client.clone(), data, None, U256::zero()).await?;

        println!(
            "deploy cdk validium deployer transaction hash:{:?}",
            transaction_hash
        );

        wait_transaction(self.client.clone(), transaction_hash).await?;

        let contract_address = get_transaction_receipt(self.client.clone(), transaction_hash)
            .await?
            .contract_address
            .ok_or(anyhow!("receipt contract_address not found"))?;

        Ok(contract_address)
    }

    async fn deploy_proxy_admin(
        &self,
        owner: H160,
        cdkvalidium_deployer_address: H160,
    ) -> Result<H160> {
        let data = DeployDeterministicAndCallCall {
            amount: U256::zero(),
            salt: self.salt,
            init_bytecode: PROXYADMIN_BYTECODE.clone(),
            data_call: TransferOwnershipCall { new_owner: owner }.encode().into(),
        }
        .encode();

        let transaction_hash = send_transaction(
            self.client.clone(),
            data,
            Some(cdkvalidium_deployer_address),
            U256::zero(),
        )
        .await?;

        wait_transaction(self.client.clone(), transaction_hash).await?;

        let logs = get_transaction_receipt(self.client.clone(), transaction_hash)
            .await?
            .logs;
        let mut contract_address = H160::zero();
        for log in logs {
            if log.address != cdkvalidium_deployer_address {
                continue;
            }

            if let Ok(decoded) = NewDeterministicDeploymentFilter::decode_log(&RawLog {
                topics: log.topics,
                data: log.data.to_vec(),
            }) {
                contract_address = decoded.new_contract_address;
                break;
            }
        }
        if contract_address.is_zero() {
            Err(anyhow!("contract_address not found"))
        } else {
            Ok(contract_address)
        }
    }

    async fn deploy_polygon_zkevm_bridge(
        &self,
        proxy_admin_address: H160,
        cdkvalidium_deployer_address: H160,
    ) -> Result<H160> {
        let contract_address = {
            let data = DeployDeterministicCall {
                amount: U256::zero(),
                salt: self.salt,
                init_bytecode: POLYGONZKEVMBRIDGE_BYTECODE.clone(),
            }
            .encode();

            let transaction_hash = send_transaction(
                self.client.clone(),
                data,
                Some(cdkvalidium_deployer_address),
                U256::zero(),
            )
            .await?;

            wait_transaction(self.client.clone(), transaction_hash).await?;

            let logs = get_transaction_receipt(self.client.clone(), transaction_hash)
                .await?
                .logs;
            let mut contract_address = H160::zero();
            for log in logs {
                if log.address != cdkvalidium_deployer_address {
                    continue;
                }

                if let Ok(decoded) = NewDeterministicDeploymentFilter::decode_log(&RawLog {
                    topics: log.topics,
                    data: log.data.to_vec(),
                }) {
                    contract_address = decoded.new_contract_address;
                    break;
                }
            }
            if contract_address.is_zero() {
                return Err(anyhow!("contract_address not found"));
            }
            contract_address
        };

        let data = DeployDeterministicCall {
            amount: U256::zero(),
            salt: self.salt,
            init_bytecode: TRANSPARENTUPGRADEABLEPROXY_BYTECODE
                .clone()
                .into_iter()
                .chain(encode(&[
                    Token::Address(contract_address),
                    Token::Address(proxy_admin_address),
                    Token::Bytes(Vec::new()),
                ]))
                .collect::<Vec<_>>()
                .into(),
        }
        .encode();

        let transaction_hash = send_transaction(
            self.client.clone(),
            data,
            Some(cdkvalidium_deployer_address),
            U256::zero(),
        )
        .await?;

        wait_transaction(self.client.clone(), transaction_hash).await?;

        let logs = get_transaction_receipt(self.client.clone(), transaction_hash)
            .await?
            .logs;
        let mut contract_address = H160::zero();
        for log in logs {
            if log.address != cdkvalidium_deployer_address {
                continue;
            }

            if let Ok(decoded) = NewDeterministicDeploymentFilter::decode_log(&RawLog {
                topics: log.topics,
                data: log.data.to_vec(),
            }) {
                contract_address = decoded.new_contract_address;
                break;
            }
        }
        if contract_address.is_zero() {
            Err(anyhow!("contract_address not found"))
        } else {
            Ok(contract_address)
        }
    }

    async fn init_polygon_zkevm_bridge(
        &self,
        polygon_zkevm_bridge_address: H160,
        global_exit_root_manager: H160,
        polygon_zkevm_address: H160,
    ) -> Result<()> {
        let call_data = polygon_zk_evm_bridge::InitializeCall {
            network_id: 0,
            global_exit_root_manager,
            polygon_zk_ev_maddress: polygon_zkevm_address,
        }
        .encode();

        let transaction_hash = send_transaction(
            self.client.clone(),
            call_data,
            Some(polygon_zkevm_bridge_address),
            U256::zero(),
        )
        .await?;

        wait_transaction(self.client.clone(), transaction_hash).await?;

        if Some(U64::one())
            != self
                .client
                .get_transaction_receipt(transaction_hash)
                .await?
                .ok_or(anyhow!("transaction receipt not found"))?
                .status
        {
            Err(anyhow!("PolygonZkEVMBridge call Initialize error"))
        } else {
            Ok(())
        }
    }

    async fn deploy_cdk_data_committee(&self, proxy_admin_address: H160) -> Result<H160> {
        let contract_address = {
            let transaction_hash = send_transaction(
                self.client.clone(),
                CDKDATACOMMITTEE_BYTECODE.to_vec(),
                None,
                U256::zero(),
            )
            .await?;

            wait_transaction(self.client.clone(), transaction_hash).await?;

            get_transaction_receipt(self.client.clone(), transaction_hash)
                .await?
                .contract_address
                .ok_or(anyhow!("receipt contract_address not found"))?
        };

        let proxy_contract_address = {
            let data = TRANSPARENTUPGRADEABLEPROXY_BYTECODE
                .clone()
                .into_iter()
                .chain(encode(&[
                    Token::Address(contract_address),
                    Token::Address(proxy_admin_address),
                    Token::Bytes(Vec::new()),
                ]))
                .collect::<Vec<_>>();

            let transaction_hash =
                send_transaction(self.client.clone(), data, None, U256::zero()).await?;

            wait_transaction(self.client.clone(), transaction_hash).await?;

            get_transaction_receipt(self.client.clone(), transaction_hash)
                .await?
                .contract_address
                .ok_or(anyhow!("receipt contract_address not found"))?
        };

        let data = SetupCommitteeCall {
            required_amount_of_signatures: U256::zero(),
            urls: Vec::new(),
            addrs_bytes: Bytes::new(),
        }
        .encode();

        let transaction_hash = send_transaction(
            self.client.clone(),
            data,
            Some(proxy_contract_address),
            U256::zero(),
        )
        .await?;
        println!(
            "call setupCommittee transaction hash:{:?}",
            transaction_hash
        );

        wait_transaction(self.client.clone(), transaction_hash).await?;

        if Some(U64::one())
            != self
                .client
                .get_transaction_receipt(transaction_hash)
                .await?
                .ok_or(anyhow!("transaction receipt not found"))?
                .status
        {
            Err(anyhow!("call setupCommittee error"))
        } else {
            Ok(proxy_contract_address)
        }
    }

    async fn deploy_polygon_zkevm_global_exit_root(
        &self,
        proxy_admin_address: H160,
        rollup_address: H160,
        bridge_address: H160,
    ) -> Result<H160> {
        let contract_address = {
            let data = POLYGONZKEVMGLOBALEXITROOT_BYTECODE
                .clone()
                .into_iter()
                .chain(encode(&[
                    Token::Address(rollup_address),
                    Token::Address(bridge_address),
                ]))
                .collect::<Vec<_>>();

            let transaction_hash =
                send_transaction(self.client.clone(), data, None, U256::zero()).await?;

            wait_transaction(self.client.clone(), transaction_hash).await?;

            get_transaction_receipt(self.client.clone(), transaction_hash)
                .await?
                .contract_address
                .ok_or(anyhow!("receipt contract_address not found"))?
        };

        let proxy_contract_address = {
            let data = TRANSPARENTUPGRADEABLEPROXY_BYTECODE
                .clone()
                .into_iter()
                .chain(encode(&[
                    Token::Address(contract_address),
                    Token::Address(proxy_admin_address),
                    Token::Bytes(Vec::new()),
                ]))
                .collect::<Vec<_>>();

            let transaction_hash =
                send_transaction(self.client.clone(), data, None, U256::zero()).await?;

            wait_transaction(self.client.clone(), transaction_hash).await?;

            get_transaction_receipt(self.client.clone(), transaction_hash)
                .await?
                .contract_address
                .ok_or(anyhow!("receipt contract_address not found"))?
        };

        Ok(proxy_contract_address)
    }

    async fn deploy_cdkvalidium(
        &self,
        proxy_admin_address: H160,
        global_exit_root_manager: H160,
        matic: H160,
        rollup_verifier: H160,
        bridge_address: H160,
        data_committee_address: H160,
    ) -> Result<H160> {
        let contract_address = {
            let data = CDKVALIDIUM_BYTECODE
                .clone()
                .into_iter()
                .chain(encode(&[
                    Token::Address(global_exit_root_manager),
                    Token::Address(matic),
                    Token::Address(rollup_verifier),
                    Token::Address(bridge_address),
                    Token::Address(data_committee_address),
                    Token::Uint(self.chain_id.into()),
                    Token::Uint(self.fork_id.into()),
                ]))
                .collect::<Vec<_>>();

            let transaction_hash =
                send_transaction(self.client.clone(), data, None, U256::zero()).await?;

            wait_transaction(self.client.clone(), transaction_hash).await?;

            get_transaction_receipt(self.client.clone(), transaction_hash)
                .await?
                .contract_address
                .ok_or(anyhow!("receipt contract_address not found"))?
        };

        let proxy_contract_address = {
            let data = TRANSPARENTUPGRADEABLEPROXY_BYTECODE
                .clone()
                .into_iter()
                .chain(encode(&[
                    Token::Address(contract_address),
                    Token::Address(proxy_admin_address),
                    Token::Bytes(Vec::new()),
                ]))
                .collect::<Vec<_>>();

            let transaction_hash =
                send_transaction(self.client.clone(), data, None, U256::zero()).await?;

            wait_transaction(self.client.clone(), transaction_hash).await?;

            get_transaction_receipt(self.client.clone(), transaction_hash)
                .await?
                .contract_address
                .ok_or(anyhow!("receipt contract_address not found"))?
        };

        Ok(proxy_contract_address)
    }

    async fn deploy_cdkvalidium_timelock(&self, cdk_validium: H160) -> Result<H160> {
        let data = CDKVALIDIUMDEPLOYER_BYTECODE
            .clone()
            .into_iter()
            .chain(encode(&[
                Token::Uint(self.min_delay.into()),
                Token::Array(vec![Token::Address(self.timelock_address)]),
                Token::Array(vec![Token::Address(self.timelock_address)]),
                Token::Address(self.timelock_address),
                Token::Address(cdk_validium),
            ]))
            .collect::<Vec<_>>();

        let transaction_hash =
            send_transaction(self.client.clone(), data, None, U256::zero()).await?;

        println!(
            "deploy cdk validium deployer transaction hash:{:?}",
            transaction_hash
        );

        wait_transaction(self.client.clone(), transaction_hash).await?;

        let contract_address = get_transaction_receipt(self.client.clone(), transaction_hash)
            .await?
            .contract_address
            .ok_or(anyhow!("receipt contract_address not found"))?;

        Ok(contract_address)
    }
}
