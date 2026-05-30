require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

const PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY || "";

function network(urlEnv, fallback) {
  const url = process.env[urlEnv] || fallback || "";
  return {
    url,
    accounts: PRIVATE_KEY ? [PRIVATE_KEY] : [],
  };
}

module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    baseSepolia: network("BASE_SEPOLIA_RPC_URL", "https://sepolia.base.org"),
    ethereumSepolia: network("ETH_SEPOLIA_RPC_URL", "https://rpc.sepolia.org"),
    arbitrumSepolia: network("ARB_SEPOLIA_RPC_URL", "https://sepolia-rollup.arbitrum.io/rpc"),
    optimismSepolia: network("OP_SEPOLIA_RPC_URL", "https://sepolia.optimism.io"),
    polygonAmoy: network("POLYGON_AMOY_RPC_URL", "https://rpc-amoy.polygon.technology"),
    avalancheFuji: network("AVAX_FUJI_RPC_URL", "https://api.avax-test.network/ext/bc/C/rpc"),
    bscTestnet: network("BSC_TESTNET_RPC_URL", "https://data-seed-prebsc-1-s1.binance.org:8545"),
  },
  etherscan: {
    apiKey: {
      baseSepolia: process.env.BASESCAN_API_KEY || "",
      ethereumSepolia: process.env.ETHERSCAN_API_KEY || "",
      arbitrumSepolia: process.env.ARBISCAN_API_KEY || "",
      optimismSepolia: process.env.OPTIMISTIC_ETHERSCAN_API_KEY || "",
      polygonAmoy: process.env.POLYGONSCAN_API_KEY || "",
      avalancheFuji: process.env.SNOWTRACE_API_KEY || "",
      bscTestnet: process.env.BSCSCAN_API_KEY || "",
    },
  },
};
