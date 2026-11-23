/*******************************************************************************
 * Copyright (c) 2016, 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.crypto.ltpakeyutil;

public final class LTPAKeyUtil {

	public static byte[] encrypt(byte[] data, byte[] key, String cipher) throws Exception {
		return LTPACrypto.encrypt(data, key, cipher);
	}

	/**
	 * Encrypt data with an explicit AES key length.
	 * Intended for the token-creation path where {@code encryptionAlg} has been
	 * resolved to {@code AES-CBC-128} or {@code AES-CBC-256}.
	 *
	 * @param data           The byte representation of the data
	 * @param key            The encryption key
	 * @param cipher         The cipher algorithm
	 * @param keyLengthBytes AES key length in bytes (16 for AES-128, 32 for AES-256)
	 * @return The encrypted data (ciphertext)
	 */
	public static byte[] encrypt(byte[] data, byte[] key, String cipher, int keyLengthBytes) throws Exception {
		return LTPACrypto.encrypt(data, key, cipher, keyLengthBytes);
	}

	public static byte[] decrypt(byte[] msg, byte[] key, String cipher) throws Exception {
		return LTPACrypto.decrypt(msg, key, cipher, 0);
	}

	/**
	 * Decrypt data with an explicit AES key length.
	 * Intended for the token-validation path where the key size is probed
	 * to handle tokens produced under a different FIPS configuration.
	 *
	 * @param msg            The byte representation of the encrypted data
	 * @param key            The decryption key
	 * @param cipher         The cipher algorithm
	 * @param keyLengthBytes AES key length in bytes (16 for AES-128, 32 for AES-256)
	 * @return The decrypted data (plaintext)
	 */
	public static byte[] decrypt(byte[] msg, byte[] key, String cipher, int keyLengthBytes) throws Exception {
		return LTPACrypto.decrypt(msg, key, cipher, keyLengthBytes);
	}

	public static boolean verifyISO9796(byte[][] key, byte[] data, int off, int len, byte[] sig, int sigOff, int sigLen)
			throws Exception {
		return LTPACrypto.verifyISO9796(key, data, off, len, sig, sigOff, sigLen);
	}

        /**
         * Encrypt data using AES-GCM (authenticated encryption).
         * PQC Issue #35556 - Task 2.6
         *
         * @param data The data to encrypt
         * @param key  The encryption key
         * @return The encrypted data with format: [IV (12 bytes)][Ciphertext][Auth Tag (16 bytes)]
         * @throws Exception if encryption fails
         */
         public static byte[] encryptGCM(byte[] data, byte[] key) throws Exception {
                 return LTPACrypto.encryptGCM(data, key);
        }

        /**
         * Decrypt data using AES-GCM (authenticated encryption).
         * PQC Issue #35556 - Task 2.6
         *
         * @param encryptedData The encrypted data
         * @param key           The decryption key
         * @return The decrypted plaintext
         * @throws Exception if decryption fails or authentication tag is invalid
         */
         public static byte[] decryptGCM(byte[] encryptedData, byte[] key) throws Exception {
                 return LTPACrypto.decryptGCM(encryptedData, key);
        }

        /**
         * Encrypts data using KDF-derived AES-GCM-256.
         * Generates a 32-byte salt, derives a per-token 256-bit AES key, and encrypts using AES-GCM.
         * Returns [Salt (32 bytes)][IV (12 bytes)][Ciphertext][Auth Tag (16 bytes)].
         *
         * @param data The plaintext data
         * @param key  The master LTPA shared key
         * @return The encrypted payload including salt, IV, ciphertext, and tag
         * @throws Exception if encryption fails
         */
        public static byte[] encryptKDF(byte[] data, byte[] key) throws Exception {
                return LTPACrypto.encryptKDF(data, key);
        }

        /**
         * Decrypts data encrypted with KDF-derived AES-GCM-256.
         * Extracts salt, derives the per-token 256-bit AES key, and decrypts using AES-GCM.
         *
         * @param encryptedData The encrypted byte payload
         * @param key           The master LTPA shared key
         * @return The decrypted plaintext
         * @throws Exception if decryption fails or authentication tag is invalid
         */
        public static byte[] decryptKDF(byte[] encryptedData, byte[] key) throws Exception {
                return LTPACrypto.decryptKDF(encryptedData, key);
        }

        /**
         * Derives a signing key from the master shared key using HKDF (HMAC-SHA256).
         *
         * @param masterKey The master LTPA shared key
         * @param sigAlg    The signature algorithm name (e.g. "AES-GCM-256")
         * @return 256-bit (32 bytes) derived signing key
         * @throws Exception if key derivation fails
         */
        public static byte[] deriveSigningKey(byte[] masterKey, String sigAlg) throws Exception {
                return LTPACrypto.deriveSigningKey(masterKey, sigAlg);
        }

        /**
         * Derives an encryption key from the master shared key using HKDF (HMAC-SHA256).
         *
         * @param masterKey      The master LTPA shared key
         * @param cipher         The cipher string or algorithm name (e.g. "AES-GCM-256", "AES-CBC-128", "AES-CBC-256")
         * @param keyLengthBytes Desired key length in bytes (16 or 32)
         * @return Derived encryption key
         * @throws Exception if key derivation fails
         */
        public static byte[] deriveEncryptionKey(byte[] masterKey, String cipher, int keyLengthBytes) throws Exception {
                return LTPACrypto.deriveEncryptionKey(masterKey, cipher, keyLengthBytes);
        }

        /**
         * Sign data using AES-GCM-256 (GMAC).
         * Computes a 128-bit (16-byte) authentication tag over {@code data} with a fresh 12-byte IV.
         * Output format: [IV (12 bytes)][Auth Tag (16 bytes)] (28 bytes total).
         *
         * @param data The data to sign
         * @param key  The derived 256-bit signing key
         * @return 28-byte signature
         * @throws Exception if signing fails
         */
        public static byte[] signGCM(byte[] data, byte[] key) throws Exception {
                return LTPACrypto.signGCM(data, key);
        }

        /**
         * Verify a signature using AES-GCM-256 (GMAC).
         * Expects [IV (12 bytes)][Auth Tag (16 bytes)] (28 bytes total).
         *
         * @param data      The data that was signed
         * @param signature The 28-byte signature (IV + Tag)
         * @param key       The derived 256-bit signing key
         * @return true if valid, false if signature is invalid or tampered
         */
        public static boolean verifyGCM(byte[] data, byte[] signature, byte[] key) {
                return LTPACrypto.verifyGCM(data, signature, key);
        }

 public static byte[] signISO9796(byte[][] key, byte[] data, int off, int len) throws Exception {
		return LTPACrypto.signISO9796(key, data, off, len);
	}

	public static void setRSAKey(byte[][] key) {
		LTPACrypto.setRSAKey(key);
	}

	public static byte[][] getRawKey(LTPAPrivateKey privKey) {
		return privKey.getRawKey();
	}

	public static byte[][] getRawKey(LTPAPublicKey pubKey) {
		return pubKey.getRawKey();
	}

	public static LTPAKeyPair generateLTPAKeyPair() {
		return LTPADigSignature.generateLTPAKeyPair();
	}

	public static byte[] generateSharedKey() {
		return LTPACrypto.generateSharedKey();
	}


}
