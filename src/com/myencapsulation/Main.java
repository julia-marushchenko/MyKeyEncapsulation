/**
 *  Java program to demonstrate KEM(key encapsulation mechanism) in 5 steps:
 *  1. Creating key pair: public and private keys.
 *  2. Generating KEM.
 *  3. Generating symmetric key with public key and KEM.
 *
 *  On receiver side:
 *  4. With KEM, public key, and KEM message generates symmetric key.
 *  5. Decapsulating secret key.
 */

package com.myencapsulation;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Main class.
 */
public class Main {

    // JVM entry point.
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException {

        /**
         * Sender side.
         */
        // Generating keypair generator with specific algorithm "X25519".
        final var keyPairGenerator = KeyPairGenerator.getInstance("X25519");

        // Generating key pair.
        final var keyPair = keyPairGenerator.generateKeyPair();

        // Generating public key.
        final var publicKey = keyPair.getPublic();

        // Generating private key.
        final var privateKey = keyPair.getPrivate();

        // Creating KEM object.
        final var senderKem = KEM.getInstance("DHKEM");

        // Generating symmetric key.
        final var sender = senderKem.newEncapsulator(publicKey);

        // Generating secret key.
        final var encapsulated = sender.encapsulate();
        final var secretKey = encapsulated.key();

        /**
         *  Receiver side. Decapsulating secret key.
         */
        // Creating KEM object.
        final var receiverKem = KEM.getInstance("DHKEM");

        // Creating symmetric key.
        final var receiver = receiverKem.newDecapsulator(privateKey);

        // Creating secret key.
        final var receivedSecretKey = receiver.decapsulate(encapsulated.encapsulation());

        // Checking if sent and received keys matching.
        if (Arrays.equals(secretKey.getEncoded(), receivedSecretKey.getEncoded())) {
            System.out.println("Keys match.");
        } else {
            System.out.println("Keys don't match.");
        }

    }
}
