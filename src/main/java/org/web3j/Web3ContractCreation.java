package org.web3j;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.generated.contracts.HelloWorld;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.RawTransactionManager;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;

public class Web3ContractCreation {

  /**
     Change HelloWorld.BINARY to your contract wrapper's binary after running the `generateContractWrapper` gradle task
   **/
  private static final String CONTRACT_BINARY = HelloWorld.BINARY;

  private static final String nodeUrl = System.getenv().getOrDefault("WEB3J_NODE_URL", "http://localhost:8545/rpc");
  private static final String CHAINID = System.getenv().getOrDefault("WEB3J_CHAINID", "1337");
  private static final String walletPassword = System.getenv().getOrDefault("WEB3J_WALLET_PASSWORD", "");
  private static final String walletPath = System.getenv().getOrDefault("WEB3J_WALLET_PATH", "test-wallet.json");

  // set following to true to use raw private key for credentials
  private static final boolean USE_PRV_KEY_CREDS = false; // use raw private key OR use wallet file
  // https://github.com/ConsenSys/quorum-dev-quickstart/blob/master/files/besu/config/besu/IBFTgenesis.json
  private static final String TEST_PRV_KEY = "ae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f";

  public static void main(String[] args) throws Exception {
    Credentials credentials = USE_PRV_KEY_CREDS ? CredentialsFactory.getCredentialsFromPrivateKey(TEST_PRV_KEY)
            : CredentialsFactory.getCredentialsFromWalletFile(walletPassword, walletPath);

    final Instant start = Instant.now();

    Web3j web3j = Web3j.build(new HttpService(nodeUrl));
    RawTransactionManager transactionManager = new RawTransactionManager(web3j, credentials, Long.parseLong(CHAINID));

    BigInteger gasPrice = BigInteger.valueOf(4100000000L);
    BigInteger gasLimit = BigInteger.valueOf(9000000L);
    String to = null;
    BigInteger value = BigInteger.ZERO;

    BigInteger initialNonce = getNonce(web3j, credentials);

    for (int i = 0; i < 1000; i++) {
      System.out.println("Deploying HelloWorld contract with nonce: " + i);

      BigInteger nonce = initialNonce.add(BigInteger.valueOf(i));
      RawTransaction rawTransaction = RawTransaction.createTransaction(nonce, gasPrice, gasLimit, to, value, CONTRACT_BINARY);
      transactionManager.signAndSend(rawTransaction);

      System.out.println("Deployed with nonce: " + i);
    }

    web3j.shutdown();
    final Instant end = Instant.now();
    final Duration timeElapsed = Duration.between(start, end);
    System.out.println("Time taken (seconds): " + timeElapsed.toSeconds());
  }

  private static BigInteger getNonce(Web3j web3j, Credentials credentials) throws IOException {
    EthGetTransactionCount ethGetTransactionCount =
        web3j.ethGetTransactionCount(
                credentials.getAddress(), DefaultBlockParameterName.PENDING)
            .send();

    return ethGetTransactionCount.getTransactionCount();
  }
}