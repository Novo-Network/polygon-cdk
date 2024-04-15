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

abigen!(
    CDKDataCommittee,
    "cdk-validium-contracts/compiled-contracts/CDKDataCommittee.json"
);

abigen!(
    PolygonZkEVMGlobalExitRoot,
    "cdk-validium-contracts/compiled-contracts/PolygonZkEVMGlobalExitRoot.json"
);

abigen!(
    CDKValidium,
    "cdk-validium-contracts/compiled-contracts/CDKValidium.json"
);

abigen!(
    CDKValidiumTimelock,
    "cdk-validium-contracts/compiled-contracts/CDKValidiumTimelock.json"
);
