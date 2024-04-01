use ethers::contract::abigen;

abigen!(
    CDKValidiumDeployer,
    "cdk-validium-contracts/compiled-contracts/CDKValidiumDeployer.json"
);

abigen!(
    ProxyAdmin,
    "cdk-validium-contracts/compiled-contracts/ProxyAdmin.json"
);

abigen!(
    PolygonZkEVMBridge,
    "cdk-validium-contracts/compiled-contracts/PolygonZkEVMBridge.json"
);

abigen!(
    TransparentUpgradeableProxy,
    "cdk-validium-contracts/compiled-contracts/TransparentUpgradeableProxy.json"
);
