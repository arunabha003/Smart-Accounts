# Smart Accounts

A modular and extensible ERC-4337 smart account implementation built with Foundry and Solady. This project provides a comprehensive smart account solution with support for Account Abstraction, paymasters, and validator plugins.

All Accounts support the following standards: ERC173, EIP712, ERC1271, ERC1822, ERC1967, ERC2098, ERC4337, ERC5267, ERC6492, ERC7582

## 🏗️ Architecture

### Core Components

- **Account.sol**: Main smart account implementation based on Solady's ERC4337 framework
- **Paymaster.sol**: ERC-4337 paymaster for sponsoring user operations
- **Validator Contracts** *(Coming Soon)*: Modular validation plugins for enhanced security



## 🚀 Quick Start

### Prerequisites
- Foundry installed ([Installation Guide](https://book.getfoundry.sh/getting-started/installation))
- Git

### Installation

```bash
git clone https://github.com/arunabha003/Smart-Accounts.git
cd Smart-Accounts
forge install
```

## 📚 Documentation

For detailed documentation on Foundry:
https://book.getfoundry.sh/

## 🛠️ Development

### Build

```bash
forge build
```

### Test

```bash
forge test
```

### Format Code

```bash
forge fmt
```

### Gas Snapshots

```bash
forge snapshot
```

### Local Development

```bash
# Start local node
anvil

# Deploy contracts (example)
forge script script/Deploy.s.sol:DeployScript --rpc-url http://localhost:8545 --private-key <your_private_key>
```

### Deploy to Network

```bash
forge script script/Deploy.s.sol:DeployScript --rpc-url <network_rpc> --private-key <your_private_key> --broadcast --verify
```

## 🔧 Contract Addresses

*Deployment addresses will be updated once contracts are deployed to networks*

## 🧪 Testing

The project includes comprehensive tests covering:
- User operation validation
- EIP-712 signature verification
- Paymaster functionality
- Edge cases and security scenarios

```bash
# Run all tests
forge test

# Run tests with gas reporting
forge test --gas-report

# Run specific test file
forge test --match-contract AccountTest
```


## ⚠️ Security Notice

This code is currently under development and has not been audited. Use at your own risk in production environments.
