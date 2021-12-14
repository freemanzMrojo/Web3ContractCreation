package org.web3j;

import lombok.extern.slf4j.Slf4j;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.generated.contracts.HelloWorld;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.Response;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.r1.ECDSASignatureR1;
import org.web3j.r1.EthPublicKeyUtils;
import org.web3j.r1.SECP256R1Sign;
import org.web3j.tx.RawTransactionManager;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;

@Slf4j
public class Web3ContractCreation {

  /**
     Change HelloWorld.BINARY to your contract wrapper's binary after running the `generateContractWrapper` gradle task
   **/
  private static final String CONTRACT_BINARY = HelloWorld.BINARY;

  private static final String nodeUrl = System.getenv().getOrDefault("WEB3J_NODE_URL", "http://localhost:8545/rpc");
  private static final String walletPassword = System.getenv().getOrDefault("WEB3J_WALLET_PASSWORD", "");
  private static final String walletPath = System.getenv().getOrDefault("WEB3J_WALLET_PATH", "test-wallet.json");

  // set following to true to use raw private key for credentials
  private static final boolean USE_PRV_KEY_CREDS = true; // use raw private key OR use wallet file
  // https://github.com/ConsenSys/quorum-dev-quickstart/blob/master/files/besu/config/besu/IBFTgenesis.json
  private static final String TEST_PRV_KEY = "db8252046e5f8e9328410d57dbe72c60b5c80958b0504d7da79bb6dfbcae5cf1";
  private static final String TEST_PUB_KEY = "f8d61b1a090ec4becb58987febc782b0730ebf1c9dbcd3b881c93fd0a16ca02b64c824b73bb4ee61f5b093db6bff658a02c777fefd5af9719f7f09da841d4f13";

  private static final Web3j besu = Web3j.build(new HttpService(nodeUrl));

  public static void main(String[] args) throws Exception {
    Credentials credentials = USE_PRV_KEY_CREDS ? CredentialsFactory.getCredentialsFromPrivateKey(TEST_PRV_KEY)
            : CredentialsFactory.getCredentialsFromWalletFile(walletPassword, walletPath);

    final Instant start = Instant.now();

    Web3j web3j = Web3j.build(new HttpService(nodeUrl));

    BigInteger gasPrice = BigInteger.valueOf(0L);
    BigInteger gasLimit = BigInteger.valueOf(2000000L);
    String to = null;
    BigInteger value = BigInteger.ZERO;

    BigInteger initialNonce = getNonce(web3j, credentials);

    for (int i = 0; i < 1000; i++) {
      System.out.println("Deploying HelloWorld contract with nonce: " + i);

      BigInteger nonce = initialNonce.add(BigInteger.valueOf(i));
      RawTransaction rawTransaction = RawTransaction.createTransaction(nonce, gasPrice, gasLimit, to, value, CONTRACT_BINARY);

      String signedTransaction = SECP256R1Sign.signTransaction(rawTransaction, TEST_PRV_KEY, TEST_PUB_KEY);
      sendRawTransaction(signedTransaction);
      System.out.println("Deployed with nonce: " + i);
    }

    web3j.shutdown();
    final Instant end = Instant.now();
    final Duration timeElapsed = Duration.between(start, end);
    System.out.println("Time taken (seconds): " + timeElapsed.toSeconds());
  }

  private static String sendRawTransaction(final String signedTransactionData) {
    final Request<?, EthSendTransaction> ethSendTransactionRequest = besu.ethSendRawTransaction(signedTransactionData);
    String message;
    try {
      final Response response = ethSendTransactionRequest.send();
      if (!response.hasError()) {
        return ((EthSendTransaction) response).getTransactionHash();
      }
      message = response.getError().getMessage();
      log.error("Sending the request to the besu network has returned a response with error(s): {}", message);
    } catch (final IOException exception) {
      message = exception.getMessage();
      log.error("An error occurred when sending the request to the besu network with method ethSendRawTransaction -\n {}", message);
    }
    return message;
  }


  private static BigInteger getNonce(Web3j web3j, Credentials credentials) throws IOException {
    EthGetTransactionCount ethGetTransactionCount =
        web3j.ethGetTransactionCount(
                credentials.getAddress(), DefaultBlockParameterName.PENDING)
            .send();

    return ethGetTransactionCount.getTransactionCount();
  }



}
