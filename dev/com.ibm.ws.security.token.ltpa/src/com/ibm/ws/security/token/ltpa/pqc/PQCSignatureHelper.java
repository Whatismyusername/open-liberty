/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
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
package com.ibm.ws.security.token.ltpa.pqc;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.concurrent.ConcurrentHashMap;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Trivial;

/**
 * Helper class for PQC signature operations using ML-DSA.
 * 
 * This class provides utility methods for signing and verifying data using
 * post-quantum cryptographic algorithms (ML-DSA) as specified in NIST FIPS 204.
 * 
 * @see <a href="https://github.ibm.com/websphere/WS-CD-Open/issues/35556">Issue #35556</a>
 */
public class PQCSignatureHelper {
    
    private static final TraceComponent tc = Tr.register(PQCSignatureHelper.class);

    // has to be greater than 0 and a multiple of 5
    private static int MAX_CACHE = 500;

    @Trivial
    private static final class MLDSAVerifyCachingKey {

        private long successfulUses;
        private final byte[] keyEncoded;
        private final byte[] data;
        private final byte[] sig;
        private final int hashcode;
        boolean result;

        @Trivial
        private MLDSAVerifyCachingKey(byte[] keyEncoded, byte[] data, byte[] sig) {
            this.keyEncoded = keyEncoded;
            this.data = data;
            this.sig = sig;
            this.successfulUses = 0;

            int h = 0;
            if (keyEncoded != null && keyEncoded.length > 0) {
                h += keyEncoded[0];
            }
            if (data != null) {
                for (int i = 0; i < data.length && i < 10; i++) {
                    h += data[i];
                }
                for (int i = data.length - 1; i >= 0 && i > data.length - 10; i--) {
                    h += data[i];
                }
            }
            h *= 2;
            this.hashcode = h;
        }

        @Trivial
        @Override
        public boolean equals(Object to) {
            if (!(to instanceof MLDSAVerifyCachingKey)) {
                return false;
            }
            MLDSAVerifyCachingKey ck = (MLDSAVerifyCachingKey) to;
            if (hashcode != ck.hashcode) {
                return false;
            }
            if (!Arrays.equals(keyEncoded, ck.keyEncoded)) {
                return false;
            }
            if (!Arrays.equals(data, ck.data)) {
                return false;
            }
            if (!Arrays.equals(sig, ck.sig)) {
                return false;
            }
            return true;
        }

        @Trivial
        @Override
        public int hashCode() {
            return hashcode;
        }
    }

    private static final ConcurrentHashMap<MLDSAVerifyCachingKey, MLDSAVerifyCachingKey> mldsaVerifyKeysMap =
            new ConcurrentHashMap<MLDSAVerifyCachingKey, MLDSAVerifyCachingKey>();

    private static final Comparator<MLDSAVerifyCachingKey> mldsaVerifyKeyComparator =
            new Comparator<MLDSAVerifyCachingKey>() {
        @Override
        @Trivial
        public int compare(MLDSAVerifyCachingKey o1, MLDSAVerifyCachingKey o2) {
            if (o1.successfulUses < o2.successfulUses) {
                return -1;
            } else if (o1.successfulUses == o2.successfulUses) {
                return 0;
            } else {
                return 1;
            }
        }
    };

    /**
     * Sign data using ML-DSA private key.
     * 
     * Implementation for Issue #35556 - Task 2.4
     * 
     * @param data Data to sign
     * @param privateKey ML-DSA private key
     * @param provider Crypto provider (OpenJCEPlus, IBMJCEPlus, or IBMJCECCA)
     * @return Signature bytes
     * @throws NoSuchAlgorithmException if ML-DSA is not supported
     * @throws NoSuchProviderException if provider is not available
     * @throws InvalidKeyException if private key is invalid
     * @throws SignatureException if signing fails
     */
    public static byte[] signMLDSA(byte[] data, PrivateKey privateKey, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException,
                   InvalidKeyException, SignatureException {
        long startSign = System.currentTimeMillis();
        String mldsaVariant = (privateKey != null) ? privateKey.getAlgorithm() : "ML-DSA";
        System.out.println("[PQCSignatureHelper] signMLDSA (" + mldsaVariant + "): start; dataLen=" + (data != null ? data.length : 0)
                + ", provider=" + provider + "; time=" + startSign + " ms");

        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "signMLDSA", "dataLength=" + (data != null ? data.length : 0), provider);
        }

        // Validate inputs
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to sign cannot be null or empty");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }

        try {
            // Get Signature instance for ML-DSA
            long startCrypto = System.currentTimeMillis();
            Signature signature = (provider != null && !provider.isEmpty())
                ? Signature.getInstance("ML-DSA", provider)
                : Signature.getInstance("ML-DSA");  // Use default SUN provider
            // Initialize with private key
            signature.initSign(privateKey);

            // Update with data to sign
            signature.update(data);

            // Generate signature
            byte[] signatureBytes = signature.sign();
            long cryptoMs = System.currentTimeMillis() - startCrypto;

            long totalMs = System.currentTimeMillis() - startSign;
            System.out.println("[PQCSignatureHelper] signMLDSA (" + mldsaVariant + "): end;"
                    + " signature=" + signatureBytes.length + " bytes"
                    + ", crypto=" + cryptoMs + " ms, total=" + totalMs + " ms");

            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA signature generated, length: " + signatureBytes.length);
            }

            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.exit(tc, "signMLDSA");
            }

            return signatureBytes;

        } catch (NoSuchAlgorithmException | NoSuchProviderException |
                 InvalidKeyException | SignatureException e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA signing failed: " + e.getMessage());
            }
            throw e;
        }
    }
    
    /**
     * Verify ML-DSA signature.
     * 
     * Implementation for Issue #35556 - Task 2.5
     * 
     * @param data Original data that was signed
     * @param signatureBytes Signature to verify
     * @param publicKey ML-DSA public key
     * @param provider Crypto provider (OpenJCEPlus, IBMJCEPlus, or IBMJCECCA)
     * @return true if signature is valid, false otherwise
     * @throws NoSuchAlgorithmException if ML-DSA is not supported
     * @throws NoSuchProviderException if provider is not available
     * @throws InvalidKeyException if public key is invalid
     * @throws SignatureException if verification fails
     */
    public static boolean verifyMLDSA(byte[] data, byte[] signatureBytes,
                                      PublicKey publicKey, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException,
                   InvalidKeyException, SignatureException {
        long startVerify = System.currentTimeMillis();
        String mldsaVariant = (publicKey != null) ? publicKey.getAlgorithm() : "ML-DSA";
        System.out.println("[PQCSignatureHelper] verifyMLDSA (" + mldsaVariant + "): start;"
                + " dataLen=" + (data != null ? data.length : 0)
                + ", sigLen=" + (signatureBytes != null ? signatureBytes.length : 0)
                + ", provider=" + provider + "; time=" + startVerify + " ms");

        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "verifyMLDSA", "dataLength=" + (data != null ? data.length : 0),
                     "signatureLength=" + (signatureBytes != null ? signatureBytes.length : 0), provider);
        }

        // Validate inputs
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to verify cannot be null or empty");
        }
        if (signatureBytes == null || signatureBytes.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }

        // Cache lookup
        long startCacheLookup = System.currentTimeMillis();
        byte[] keyEncoded = publicKey.getEncoded();
        MLDSAVerifyCachingKey ck = new MLDSAVerifyCachingKey(keyEncoded, data, signatureBytes);
        MLDSAVerifyCachingKey cached = mldsaVerifyKeysMap.get(ck);
        long cacheLookupMs = System.currentTimeMillis() - startCacheLookup;
        System.out.println("[PQCSignatureHelper] verifyMLDSA: cache lookup took " + cacheLookupMs + " ms");

        if (cached != null) {
            cached.successfulUses += 1;
            System.out.println("[PQCSignatureHelper] verifyMLDSA: cache hit; total=" + (System.currentTimeMillis() - startVerify) + " ms");
            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.exit(tc, "verifyMLDSA", "cache hit: " + cached.result);
            }
            return cached.result;
        }

        // Evict bottom 20% if at capacity
        long evictionMs = 0;
        if (mldsaVerifyKeysMap.size() >= MAX_CACHE) {
            long startEviction = System.currentTimeMillis();
            int mapSize = mldsaVerifyKeysMap.size();
            MLDSAVerifyCachingKey[] keys = mldsaVerifyKeysMap.keySet().toArray(new MLDSAVerifyCachingKey[mapSize]);
            Arrays.sort(keys, mldsaVerifyKeyComparator);
            if (mldsaVerifyKeyComparator.compare(keys[0], keys[keys.length - 1]) < 0) {
                for (int i = 0; i < mapSize / 5; i++) {
                    mldsaVerifyKeysMap.remove(keys[i]);
                    keys[i + 1 * mapSize / 5].successfulUses--;
                    keys[i + 2 * mapSize / 5].successfulUses--;
                    keys[i + 3 * mapSize / 5].successfulUses--;
                    keys[i + 4 * mapSize / 5].successfulUses--;
                }
            } else { // TODO: consider removing bc this likely isn't used since we sort the keys above (except when all keys have the same num of uses)
                for (int i = 0; i < mapSize / 5; i++) {
                    mldsaVerifyKeysMap.remove(keys[keys.length - 1 - i]);
                    keys[keys.length - 1 - i - 1 * mapSize / 5].successfulUses--;
                    keys[keys.length - 1 - i - 2 * mapSize / 5].successfulUses--;
                    keys[keys.length - 1 - i - 3 * mapSize / 5].successfulUses--;
                    keys[keys.length - 1 - i - 4 * mapSize / 5].successfulUses--;
                }
            }
            evictionMs = System.currentTimeMillis() - startEviction;
            System.out.println("[PQCSignatureHelper] verifyMLDSA: cache eviction took " + evictionMs + " ms");
        }

        try {
            // Get Signature instance for ML-DSA
            long startCrypto = System.currentTimeMillis();
            Signature signature = (provider != null && !provider.isEmpty())
                ? Signature.getInstance("ML-DSA", provider)
                : Signature.getInstance("ML-DSA");  // Use default SUN provider
            // Initialize with public key
            signature.initVerify(publicKey);

            // Update with data
            signature.update(data);

            // Verify signature
            boolean isValid = signature.verify(signatureBytes);
            long cryptoMs = System.currentTimeMillis() - startCrypto;
            System.out.println("[PQCSignatureHelper] verifyMLDSA: crypto (getInstance+initVerify+update+verify) took " + cryptoMs + " ms");

            // Store result in cache
            mldsaVerifyKeysMap.put(ck, ck);
            ck.result = isValid;
            ck.successfulUses = 0;

            long totalMs = System.currentTimeMillis() - startVerify;
            System.out.println("[PQCSignatureHelper] verifyMLDSA (" + mldsaVariant + "): end;"
                    + " valid=" + isValid + ", cacheLookup=" + cacheLookupMs + " ms, eviction=" + evictionMs
                    + " ms, crypto=" + cryptoMs + " ms, total=" + totalMs + " ms");

            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA signature verification result: " + isValid);
            }

            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.exit(tc, "verifyMLDSA", isValid);
            }

            return isValid;

        } catch (NoSuchAlgorithmException | NoSuchProviderException |
                 InvalidKeyException | SignatureException e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA verification failed: " + e.getMessage());
            }
            throw e;
        }
    }
    
    /**
     * Sign data using hybrid approach (both RSA and ML-DSA).
     *
     * Implementation for Issue #35556 - Task 2.4: Hybrid signing
     *
     * The hybrid signature format is:
     * [4 bytes: RSA signature length][RSA signature][ML-DSA signature]
     *
     * @param data Data to sign
     * @param rsaPrivateKey RSA private key (LTPAPrivateKey)
     * @param mldsaPrivateKey ML-DSA private key
     * @param provider Crypto provider for ML-DSA
     * @return Combined signature containing both RSA and ML-DSA signatures
     */
    public static byte[] signHybrid(byte[] data, Object rsaPrivateKey,
                                   PrivateKey mldsaPrivateKey, String provider)
            throws Exception {
        long startHybridSign = System.currentTimeMillis();
        System.out.println("[PQCSignatureHelper] signHybrid (RSA+" + "ML-DSA): start; dataLen=" + (data != null ? data.length : 0)
                + ", provider=" + provider + "; time=" + startHybridSign + " ms");

        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "signHybrid", "dataLength=" + (data != null ? data.length : 0), provider);
        }

        // Validate inputs
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to sign cannot be null or empty");
        }
        if (rsaPrivateKey == null) {
            throw new IllegalArgumentException("RSA private key cannot be null");
        }
        if (mldsaPrivateKey == null) {
            throw new IllegalArgumentException("ML-DSA private key cannot be null");
        }
        if (provider == null || provider.isEmpty()) {
            throw new IllegalArgumentException("Provider cannot be null or empty");
        }

        try {
            // 1. Sign with RSA using existing Liberty LTPA code
            long startRsa = System.currentTimeMillis();
            byte[] rsaSignature = signRSA(data, rsaPrivateKey);
            long rsaMs = System.currentTimeMillis() - startRsa;
            System.out.println("[PQCSignatureHelper] signHybrid: RSA sign took " + rsaMs + " ms; sigLen=" + rsaSignature.length + " bytes");

            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "RSA signature generated, length: " + rsaSignature.length);
            }

            // 2. Sign with ML-DSA
            long startMldsa = System.currentTimeMillis();
            byte[] mldsaSignature = signMLDSA(data, mldsaPrivateKey, provider);
            long mldsaMs = System.currentTimeMillis() - startMldsa;
            System.out.println("[PQCSignatureHelper] signHybrid: ML-DSA sign took " + mldsaMs + " ms; sigLen=" + mldsaSignature.length + " bytes");

            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA signature generated, length: " + mldsaSignature.length);
            }

            // 3. Combine both signatures: [4 bytes: RSA length][RSA sig][ML-DSA sig]
            byte[] hybridSignature = combineSignatures(rsaSignature, mldsaSignature);

            long totalMs = System.currentTimeMillis() - startHybridSign;
            System.out.println("[PQCSignatureHelper] signHybrid (RSA+ML-DSA): end;"
                    + " hybridSigLen=" + hybridSignature.length + " bytes"
                    + ", rsa=" + rsaMs + " ms, mldsa=" + mldsaMs + " ms, total=" + totalMs + " ms");

            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Hybrid signature created, total length: " + hybridSignature.length);
            }

            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.exit(tc, "signHybrid");
            }

            return hybridSignature;

        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Hybrid signing failed: " + e.getMessage());
            }
            throw e;
        }
    }
 
    /**
     * Verify hybrid signature (both RSA and ML-DSA).
     *
     * Implementation for Issue #35556 - Task 2.5: Hybrid verification
     *
     * @param data Original data
     * @param hybridSignature Combined signature in format: [4 bytes: RSA length][RSA sig][ML-DSA sig]
     * @param rsaPublicKey RSA public key (LTPAPublicKey)
     * @param mldsaPublicKey ML-DSA public key
     * @param provider Crypto provider for ML-DSA
     * @return true if both signatures are valid
     */
    public static boolean verifyHybrid(byte[] data, byte[] hybridSignature,
                                      Object rsaPublicKey, PublicKey mldsaPublicKey,
                                      String provider)
            throws Exception {
        long startHybridVerify = System.currentTimeMillis();
        System.out.println("[PQCSignatureHelper] verifyHybrid (RSA+ML-DSA): start;"
                + " dataLen=" + (data != null ? data.length : 0)
                + ", hybridSigLen=" + (hybridSignature != null ? hybridSignature.length : 0)
                + ", provider=" + provider + "; time=" + startHybridVerify + " ms");

        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "verifyHybrid", "dataLength=" + (data != null ? data.length : 0),
                     "signatureLength=" + (hybridSignature != null ? hybridSignature.length : 0), provider);
        }

        // Validate inputs
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to verify cannot be null or empty");
        }
        if (hybridSignature == null || hybridSignature.length < 5) {
            throw new IllegalArgumentException("Hybrid signature is invalid or too short");
        }
        if (rsaPublicKey == null) {
            throw new IllegalArgumentException("RSA public key cannot be null");
        }
        if (mldsaPublicKey == null) {
            throw new IllegalArgumentException("ML-DSA public key cannot be null");
        }
        if (provider == null || provider.isEmpty()) {
            throw new IllegalArgumentException("Provider cannot be null or empty");
        }

        try {
            // 1. Split combined signature into RSA and ML-DSA parts
            byte[][] signatures = splitSignatures(hybridSignature);
            byte[] rsaSignature = signatures[0];
            byte[] mldsaSignature = signatures[1];

            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Split signatures - RSA length: " + rsaSignature.length +
                         ", ML-DSA length: " + mldsaSignature.length);
            }

            // 2. Verify RSA signature using existing Liberty code
            long startRsa = System.currentTimeMillis();
            boolean rsaValid = verifyRSA(data, rsaSignature, rsaPublicKey);
            long rsaMs = System.currentTimeMillis() - startRsa;
            System.out.println("[PQCSignatureHelper] verifyHybrid: RSA verify took " + rsaMs + " ms; valid=" + rsaValid);

            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "RSA signature verification: " + rsaValid);
            }

            // 3. Verify ML-DSA signature
            long startMldsa = System.currentTimeMillis();
            boolean mldsaValid = verifyMLDSA(data, mldsaSignature, mldsaPublicKey, provider);
            long mldsaMs = System.currentTimeMillis() - startMldsa;
            System.out.println("[PQCSignatureHelper] verifyHybrid: ML-DSA verify took " + mldsaMs + " ms; valid=" + mldsaValid);

            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA signature verification: " + mldsaValid);
            }

            // 4. Both must be valid for hybrid verification to succeed
            boolean isValid = rsaValid && mldsaValid;

            long totalMs = System.currentTimeMillis() - startHybridVerify;
            System.out.println("[PQCSignatureHelper] verifyHybrid (RSA+ML-DSA): end;"
                    + " valid=" + isValid + ", rsa=" + rsaMs + " ms, mldsa=" + mldsaMs + " ms, total=" + totalMs + " ms");

            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.exit(tc, "verifyHybrid", isValid);
            }

            return isValid;

        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Hybrid verification failed: " + e.getMessage());
            }
            throw e;
        }
    }
        
  
    /**
     * Get expected signature size for ML-DSA algorithm.
     * 
     * @param algorithm ML-DSA algorithm variant
     * @return Expected signature size in bytes
     */
    @Trivial
    public static int getMLDSAVerifyCacheSize() {
        return mldsaVerifyKeysMap.size();
    }

    @Trivial
    public static void emptyMLDSAVerifyCache() {
        mldsaVerifyKeysMap.clear();
    }

    public static int getMLDSASignatureSize(String algorithm) {
        if (PQCConstants.ALGORITHM_ML_DSA_44.equals(algorithm)) {
            return 2420; // ML-DSA-44 signature size
        } else if (PQCConstants.ALGORITHM_ML_DSA_65.equals(algorithm)) {
            return 3309; // ML-DSA-65 signature size
        } else if (PQCConstants.ALGORITHM_ML_DSA_87.equals(algorithm)) {
            return 4627; // ML-DSA-87 signature size
        }
        throw new IllegalArgumentException("Unknown ML-DSA algorithm: " + algorithm);
    }

// ========== Private Helper Methods ==========

    /**
     * Sign data using RSA (delegates to existing Liberty LTPA code).
     *
     * @param data Data to sign
     * @param rsaPrivateKey LTPAPrivateKey object
     * @return RSA signature bytes
     */
    private static byte[] signRSA(byte[] data, Object rsaPrivateKey) throws Exception {
        java.security.MessageDigest md = com.ibm.ws.common.crypto.CryptoUtils.getMessageDigestForLTPA();
        byte[] digest = md.digest(data);

        byte[][] rsaPrivKey = com.ibm.ws.crypto.ltpakeyutil.LTPAKeyUtil.getRawKey(
            (com.ibm.ws.crypto.ltpakeyutil.LTPAPrivateKey) rsaPrivateKey);
        com.ibm.ws.crypto.ltpakeyutil.LTPAKeyUtil.setRSAKey(rsaPrivKey);

        return com.ibm.ws.crypto.ltpakeyutil.LTPAKeyUtil.signISO9796(
            rsaPrivKey, digest, 0, digest.length);
    }

   /**
     * Verify RSA signature (delegates to existing Liberty LTPA code).
     */
    private static boolean verifyRSA(byte[] data, byte[] signature, Object rsaPublicKey) throws Exception {
        java.security.MessageDigest md = com.ibm.ws.common.crypto.CryptoUtils.getMessageDigestForLTPA();
        byte[] digest = md.digest(data);

        byte[][] rsaPubKey = com.ibm.ws.crypto.ltpakeyutil.LTPAKeyUtil.getRawKey(
            (com.ibm.ws.crypto.ltpakeyutil.LTPAPublicKey) rsaPublicKey);

        return com.ibm.ws.crypto.ltpakeyutil.LTPAKeyUtil.verifyISO9796(
            rsaPubKey, digest, 0, digest.length, signature, 0, signature.length);
    }

    /**
     * Combine RSA and ML-DSA signatures into hybrid format.
     */
    private static byte[] combineSignatures(byte[] rsaSignature, byte[] mldsaSignature) {
        int rsaLength = rsaSignature.length;
        int totalLength = 4 + rsaLength + mldsaSignature.length;
        byte[] combined = new byte[totalLength];

        combined[0] = (byte) (rsaLength >> 24);
        combined[1] = (byte) (rsaLength >> 16);
        combined[2] = (byte) (rsaLength >> 8);
        combined[3] = (byte) rsaLength;

        System.arraycopy(rsaSignature, 0, combined, 4, rsaLength);
        System.arraycopy(mldsaSignature, 0, combined, 4 + rsaLength, mldsaSignature.length);

        return combined;
    }

    /**
     * Split hybrid signature into RSA and ML-DSA components.
     */
    private static byte[][] splitSignatures(byte[] hybridSignature) {
        if (hybridSignature.length < 5) {
            throw new IllegalArgumentException("Hybrid signature too short");
        }

        int rsaLength = ((hybridSignature[0] & 0xFF) << 24) |
                       ((hybridSignature[1] & 0xFF) << 16) |
                       ((hybridSignature[2] & 0xFF) << 8) |
                       (hybridSignature[3] & 0xFF);

        if (rsaLength < 0 || rsaLength > hybridSignature.length - 4) {
            throw new IllegalArgumentException("Invalid RSA signature length");
        }

        byte[] rsaSignature = new byte[rsaLength];
        System.arraycopy(hybridSignature, 4, rsaSignature, 0, rsaLength);

        int mldsaLength = hybridSignature.length - 4 - rsaLength;
        byte[] mldsaSignature = new byte[mldsaLength];
        System.arraycopy(hybridSignature, 4 + rsaLength, mldsaSignature, 0, mldsaLength);

        return new byte[][] { rsaSignature, mldsaSignature };
    }

}
