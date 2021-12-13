# Web3j Contract Creation Demo

## Overview
This demo adapts the [Web3j quickstart HelloWorld example](http://docs.web3j.io/4.8.7/quickstart/#deploying-a-smart-contract) to send 1000 contract creations in quick succession.
This code manages the nonce and uses the encoded contract data to create a transaction, sign and send it without waiting for transaction receipts.

It is intended to test behaviour of an Ethereum network for development/testing purposes.

## Running contract deployment of the HelloWorld example

The following environment variables can be set, otherwise their default value in parentheses will be used.

- WEB3J_NODE_URL ("http://localhost:8545") - point this at your Ethereum network
- WEB3J_WALLET_PASSWORD ("")
- WEB3J_WALLET_PATH" ("test-wallet.json")

test-wallet.json is included in this project, it was created with the [web3j cli](http://docs.web3j.io/4.8.7/command_line_tools/#wallet-tools) `web3j wallet create`
Your running Ethereum network may need to allocate this wallet's address some funds for the contract creation to work.

This project can also use raw private key instead of wallet file. Manually assign `org.web3j.Web3ContractCreation.USE_PRV_KEY_CREDS` to `true`
and update value of `org.web3j.Web3ContractCreation.TEST_PRV_KEY`

If it's your first run, you'll need to generate the HelloWorld contract wrapper:
`./gradlew generateContractWrappers`

Alternatively, you can use your own contract following the instructions below.

Finally, run `Web3ContractCreation.main`

## Running contract deployment for your own Contract
1. Add your .sol contract to src/main/solidity
2. Run `./gradlew generateContractWrappers`
3. In `Web3ContractCreation.main`, change `HelloWorld.BINARY` to your contract wrapper's binary