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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.KeyPair;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Properties;

import com.ibm.ws.common.crypto.CryptoUtils;
import com.ibm.ws.common.encoder.Base64Coder;

/**
 *
 */
public class LTPAKeyFileUtilityImpl implements LTPAKeyFileUtility {

	/** {@inheritDoc} */
	@Override
	public Properties createLTPAKeysFile(String keyFile, byte[] keyPasswordBytes) throws Exception {
		Properties ltpaProps = generateLTPAKeys(keyPasswordBytes, "defaultRealm");
		addLTPAKeysToFile(getOutputStream(keyFile), ltpaProps);
		return ltpaProps;
	}

	/**
	 * Generates the LTPA keys and stores them into a Properties object.
	 *
	 * @param keyPasswordBytes
	 * @param realm
	 * @return
	 * @throws Exception
	 */
	protected final Properties generateLTPAKeys(byte[] keyPasswordBytes, final String realm) throws Exception {
		return generateLTPAKeys(keyPasswordBytes, null, null, null, realm, "classical", null, 0);
	}

	/**
	 * Generates the LTPA keys and stores them into a Properties object.
	 *
	 * In the case of generating new ltpa keys, pass null in sharedKeyBytes,
	 * privateKeyBytes, and publicKeyBytes to generate them.
	 *
	 * Otherwise, in the case of re-encrypting existing ltpa keys, pass the bytes in
	 * sharedKeyBytes, privateKeyBytes, and publicKeyBytes to reuse them.
	 *
	 * @param keyPasswordBytes  password used to encrypt stored private keys
	 * @param sharedKeyBytes    existing shared key, or {@code null} to generate
	 * @param privateKeyBytes   existing RSA private key, or {@code null} to generate (classical only)
	 * @param publicKeyBytes    existing RSA public key, or {@code null} to generate (classical only)
	 * @param realm             realm name stored in the key file
	 * @param signingMode       signing mode ("classical", "pqc", "hybrid", "symmetric", "none"); null is
	 *                          treated as "classical". The mode alone selects the key file format:
	 *                          <ul>
	 *                          <li>classical, none: v1.0/v2.0 RSA key file; {@code mldsaAlgorithm} is ignored</li>
	 *                          <li>pqc: v3.0 ML-DSA key file; requires {@code mldsaAlgorithm}; {@code classicalKeySize} is ignored</li>
	 *                          <li>hybrid: v3.0 ML-DSA + RSA key file; requires {@code mldsaAlgorithm} and {@code classicalKeySize > 0}</li>
	 *                          <li>symmetric: v4.0 shared-key-only file; {@code mldsaAlgorithm} and {@code classicalKeySize} are ignored</li>
	 *                          </ul>
	 * @param mldsaAlgorithm    ML-DSA algorithm (e.g. "ML-DSA-65"); required for pqc and hybrid
	 * @param classicalKeySize  RSA key size in bytes (128=RSA-1024, 256=RSA-2048); for classical/none 0 uses the default,
	 *                          for hybrid it must be positive
	 * @return Properties containing all LTPA key attributes
	 * @throws IllegalArgumentException if signingMode is unknown or required arguments for the mode are missing
	 * @throws Exception
	 */
	protected final Properties generateLTPAKeys(byte[] keyPasswordBytes, byte[] sharedKeyBytes, byte[] privateKeyBytes,
			byte[] publicKeyBytes, final String realm, String signingMode, String mldsaAlgorithm, int classicalKeySize) throws Exception {
		String mode = (signingMode == null) ? "classical" : signingMode.toLowerCase(java.util.Locale.ENGLISH);
		switch (mode) {
			case "classical":
			case "none":
			case "symmetric":
				break;
			case "pqc":
			case "hybrid":
				if (mldsaAlgorithm == null) {
					throw new IllegalArgumentException("signingMode=" + signingMode + " requires an ML-DSA algorithm");
				}
				if ("hybrid".equals(mode) && classicalKeySize <= 0) {
					throw new IllegalArgumentException("signingMode=hybrid requires a positive classicalKeySize");
				}
				break;
			default:
				throw new IllegalArgumentException("Unsupported signingMode: " + signingMode);
		}

		long startGenerate = System.currentTimeMillis();
		System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys: start; signingMode=" + signingMode
				+ ", mldsaAlgorithm=" + mldsaAlgorithm + ", classicalKeySize=" + classicalKeySize + "; time=" + startGenerate + " ms");

		Properties expProps = null;

		try {
			// KeyEncryptor construction (password-based key derivation via SHA-256)
			long startEncryptor = System.currentTimeMillis();
			KeyEncryptor encryptor = new KeyEncryptor(keyPasswordBytes);
			long encryptorMs = System.currentTimeMillis() - startEncryptor;
			System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys: KeyEncryptor construction (SHA-256 digest) took " + encryptorMs + " ms");

			// Shared AES key — always required for token payload encryption.
			long sharedKeyMs = 0;
			if (sharedKeyBytes == null) {
				long startSharedKey = System.currentTimeMillis();
				sharedKeyBytes = LTPACrypto.generateSharedKey();
				sharedKeyMs = System.currentTimeMillis() - startSharedKey;
				System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys: AES-256 shared key generation took " + sharedKeyMs + " ms");
			} else {
				System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys: shared key reused (skipped generation)");
			}

			expProps = new Properties();
			expProps.put(KEYIMPORT_REALM, realm);
			expProps.put(CREATION_HOST_PROPERTY, "localhost");
			expProps.put(CREATION_DATE_PROPERTY, (new java.util.Date()).toString());

			if ("symmetric".equals(mode)) {
				// v4.0 = Pure Symmetric (Master Shared Key only, no RSA or ML-DSA keys).
				// Key encrypting algorithm: always AES-CBC-256 for v4.0 key files.
				String keyEncAlgorithm = "AES-CBC-256";
				expProps.put(LTPA_VERSION_PROPERTY, "4.0");

				// Shared key encryption
				long startSharedEncrypt = System.currentTimeMillis();
				expProps.put(KEYIMPORT_SECRETKEY_V1,
				             Base64Coder.base64EncodeToString(encryptor.encryptAES(sharedKeyBytes)));
				long sharedEncryptMs = System.currentTimeMillis() - startSharedEncrypt;
				System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys: shared key encryption (keyEncAlgorithm=" + keyEncAlgorithm + ") took " + sharedEncryptMs + " ms");

				long totalMs = System.currentTimeMillis() - startGenerate;
				System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys (v4.0 Symmetric, keyEncAlgorithm=" + keyEncAlgorithm + "): end;"
						+ " encryptor=" + encryptorMs + " ms, sharedKey=" + sharedKeyMs + " ms, sharedEncrypt=" + sharedEncryptMs
						+ " ms, total=" + totalMs + " ms");
			} else if ("classical".equals(mode) || "none".equals(mode)) {
				int rsaKeySize = (classicalKeySize == 0) ? LTPADigSignature.keySize : classicalKeySize;
				// v2.0 = RSA-2048 (rsaKeySize >= 256 bytes).
				// v1.0 = RSA-1024 (rsaKeySize < 256 bytes).
				boolean rsa2048 = (rsaKeySize >= 256);
				expProps.put(LTPA_VERSION_PROPERTY, rsa2048 ? "2.0" : "1.0");
				// Key encrypting algorithm: AES-CBC-256 for v2.0; FIPS-aware cipher for v1.0
				String keyEncAlgorithm = rsa2048 ? "AES-CBC-256" : CryptoUtils.getCipher();

				// Shared key encryption
				long startSharedEncrypt = System.currentTimeMillis();
				if (rsa2048) {
					// v2.0: encrypt with AES regardless of FIPS mode so any server can load the file.
					expProps.put(KEYIMPORT_SECRETKEY_V2,
					             Base64Coder.base64EncodeToString(encryptor.encryptAES(sharedKeyBytes)));
				} else {
					// v1.0: legacy DES/AES encryption determined by FIPS mode.
					expProps.put(KEYIMPORT_SECRETKEY_V1,
					             Base64Coder.base64EncodeToString(encryptor.encrypt(sharedKeyBytes)));
				}
				long sharedEncryptMs = System.currentTimeMillis() - startSharedEncrypt;
				System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys: shared key encryption (keyEncAlgorithm=" + keyEncAlgorithm + ") took " + sharedEncryptMs + " ms");

				// RSA key pair generation (only when keys are not being reused)
				long keyPairMs = 0;
				if (publicKeyBytes == null && privateKeyBytes == null) {
					long startKeyPair = System.currentTimeMillis();
					LTPAKeyPair pair = LTPADigSignature.generateLTPAKeyPair(rsaKeySize);
					publicKeyBytes = pair.getPublic().getEncoded();
					privateKeyBytes = pair.getPrivate().getEncoded();
					keyPairMs = System.currentTimeMillis() - startKeyPair;
					System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys: RSA-" + (rsaKeySize * 8) + " key pair generation took " + keyPairMs + " ms");
				} else {
					System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys: RSA key pair reused (skipped generation)");
				}

				// Private key encryption
				long startPrivateEncrypt = System.currentTimeMillis();
				byte[] encryptedPrivateKeyBytes = rsa2048
				        ? encryptor.encryptAES(privateKeyBytes)
				        : encryptor.encrypt(privateKeyBytes);
				long privateEncryptMs = System.currentTimeMillis() - startPrivateEncrypt;
				System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys: RSA private key encryption (keyEncAlgorithm=" + keyEncAlgorithm + ") took " + privateEncryptMs + " ms");

				expProps.put(KEYIMPORT_PRIVATEKEY, Base64Coder.base64EncodeToString(encryptedPrivateKeyBytes));
				expProps.put(KEYIMPORT_PUBLICKEY, Base64Coder.base64EncodeToString(publicKeyBytes));

				long totalMs = System.currentTimeMillis() - startGenerate;
				System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys (RSA-" + (rsaKeySize * 8) + ", keyEncAlgorithm=" + keyEncAlgorithm + "): end;"
						+ " encryptor=" + encryptorMs + " ms, sharedKey=" + sharedKeyMs + " ms, sharedEncrypt=" + sharedEncryptMs
						+ " ms, keyPair=" + keyPairMs + " ms, privateEncrypt=" + privateEncryptMs + " ms, total=" + totalMs + " ms");
			} else {
				// v3.0 = PQC (ML-DSA keys only, no RSA keys).
				// Key encrypting algorithm: always AES-CBC-256 for PQC key files.
				String keyEncAlgorithm = "AES-CBC-256";

				// Encrypt with AES regardless of FIPS mode so any server can load the file.
				expProps.put(LTPA_VERSION_PROPERTY, "3.0");

				// Shared key encryption
				long startSharedEncrypt = System.currentTimeMillis();
				expProps.put(KEYIMPORT_SECRETKEY_V1,
				             Base64Coder.base64EncodeToString(encryptor.encryptAES(sharedKeyBytes)));
				long sharedEncryptMs = System.currentTimeMillis() - startSharedEncrypt;
				System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys: shared key encryption (keyEncAlgorithm=" + keyEncAlgorithm + ") took " + sharedEncryptMs + " ms");

				// ML-DSA key pair generation
				long startMLDSAKeyPair = System.currentTimeMillis();
				KeyPair mldsaKeyPair = generateMLDSAKeyPair(mldsaAlgorithm);
				long mldsaKeyPairMs = System.currentTimeMillis() - startMLDSAKeyPair;
				System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys: " + mldsaAlgorithm + " key pair generation took " + mldsaKeyPairMs + " ms");

				if (mldsaKeyPair != null) {
					// ML-DSA private key encryption
					long startMLDSAEncrypt = System.currentTimeMillis();
					byte[] encryptedMLDSAPrivateKeyBytes = encryptor.encryptAES(mldsaKeyPair.getPrivate().getEncoded());
					long mldsaEncryptMs = System.currentTimeMillis() - startMLDSAEncrypt;
					System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys: " + mldsaAlgorithm + " private key encryption (keyEncAlgorithm=" + keyEncAlgorithm + ") took " + mldsaEncryptMs + " ms");

					expProps.put(KEYIMPORT_MLDSA_PUBLICKEY, Base64Coder.base64EncodeToString(mldsaKeyPair.getPublic().getEncoded()));
					expProps.put(KEYIMPORT_MLDSA_PRIVATEKEY, Base64Coder.base64EncodeToString(encryptedMLDSAPrivateKeyBytes));
				}

				// RSA key pair generation: only when classicalKeySize > 0 (Hybrid mode)
				if ("hybrid".equals(mode)) {
					long keyPairMs = 0;
					if (publicKeyBytes == null && privateKeyBytes == null) {
						long startKeyPair = System.currentTimeMillis();
						LTPAKeyPair pair = LTPADigSignature.generateLTPAKeyPair(classicalKeySize);
						publicKeyBytes = pair.getPublic().getEncoded();
						privateKeyBytes = pair.getPrivate().getEncoded();
						keyPairMs = System.currentTimeMillis() - startKeyPair;
						System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys (hybrid): RSA-" + (classicalKeySize * 8) + " key pair generation took " + keyPairMs + " ms");
					} else {
						System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys (hybrid): RSA key pair reused (skipped generation)");
					}

					if (privateKeyBytes != null) {
						long startPrivateEncrypt = System.currentTimeMillis();
						byte[] encryptedPrivateKeyBytes = encryptor.encryptAES(privateKeyBytes);
						long privateEncryptMs = System.currentTimeMillis() - startPrivateEncrypt;
						System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys (hybrid): RSA private key encryption took " + privateEncryptMs + " ms");

						expProps.put(KEYIMPORT_PRIVATEKEY, Base64Coder.base64EncodeToString(encryptedPrivateKeyBytes));
						expProps.put(KEYIMPORT_PUBLICKEY, Base64Coder.base64EncodeToString(publicKeyBytes));
					}
				}

				long totalMs = System.currentTimeMillis() - startGenerate;
				System.out.println("[LTPAKeyFileUtilityImpl] generateLTPAKeys (" + mldsaAlgorithm + ("hybrid".equals(mode) ? (" + RSA-" + (classicalKeySize * 8)) : "") + ", keyEncAlgorithm=" + keyEncAlgorithm + "): end;"
						+ " encryptor=" + encryptorMs + " ms, sharedKey=" + sharedKeyMs + " ms, sharedEncrypt=" + sharedEncryptMs
						+ " ms, mldsaKeyPair=" + mldsaKeyPairMs + " ms, total=" + totalMs + " ms");
			}
		} catch (Exception e) {
			throw e;
		}

		return expProps;
	}

	/**
	 * Obtain the OutputStream for the given file.
	 *
	 * @param keyFile
	 * @return
	 * @throws IOException
	 */
	private OutputStream getOutputStream(final String keyFile) throws IOException {
		try {
			return AccessController.doPrivileged(new PrivilegedExceptionAction<OutputStream>() {
				@Override
				public OutputStream run() throws IOException {
					return new FileOutputStream(new File(keyFile));
				}
			});
		} catch (PrivilegedActionException e) {
			// Wrap the wrapped IOException from doPriv in an IOException and re-throw
			throw new IOException(e.getCause());
		}
	}

	/**
	 * Write the LTPA key properties to the given OutputStream. This method will
	 * close the OutputStream.
	 *
	 * @param keyImportFile The import file to be created
	 * @param ltpaProps     The properties containing the LTPA keys
	 *
	 * @throws TokenException
	 * @throws IOException
	 */
	protected void addLTPAKeysToFile(OutputStream os, Properties ltpaProps) throws Exception {
		try {
			// Write the ltpa key propeperties to
			ltpaProps.store(os, null);
		} catch (IOException e) {
			throw e;
		} finally {
			if (os != null)
				try {
					os.close();
				} catch (IOException e) {
				}
		}

		return;
	}

	/**
	 * Generate an ML-DSA key pair for PQC support.
	 *
	 * @param algorithm ML-DSA algorithm name (e.g. "ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
	 * @return KeyPair containing ML-DSA public and private keys, or null if generation fails
	 */
	private KeyPair generateMLDSAKeyPair(String algorithm) {
		try {
			java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance(algorithm);
			return keyGen.generateKeyPair();
		} catch (java.security.NoSuchAlgorithmException e) {
			return null;
		} catch (Exception e) {
			return null;
		}
	}
}
