package org.web3j;

import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;

import java.io.IOException;

public class CredentialsFactory {
    public static Credentials getCredentialsFromWalletFile(final String password, final String source) throws CipherException, IOException {
        return  WalletUtils.loadCredentials(password, source);
    }

    public static Credentials getCredentialsFromPrivateKey(final String privateKey) {
       return Credentials.create(privateKey);
    }
}
