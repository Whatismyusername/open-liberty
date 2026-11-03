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
package com.ibm.ws.security.token.ltpa.internal;

import com.ibm.websphere.security.auth.InvalidTokenException;
import com.ibm.ws.common.crypto.CryptoUtils;

/**
 * Defines the LTPAToken2 algorithm header wire format and provides encode/decode
 * helpers for the 7-byte plaintext prefix that is prepended to every new token.
 *
 * <h2>Wire format</h2>
 * <pre>
 * [ Magic: 4 bytes ][ Version: 1 byte ][ SigAlg: 1 byte ][ EncAlg: 1 byte ][ Ciphertext ... ]
 *   'L' 'T' 'P' 'A'      0x01           see SIG_ALG_*       see ENC_ALG_*
 *   |&lt;————————— plaintext, never encrypted ————————&gt;|&lt;——— encrypted blob ———&gt;|
 * </pre>
 *
 */
public final class LTPATokenHeader {

    public static final byte[] HEADER_MAGIC = { (byte) 0x4C, (byte) 0x54, (byte) 0x50, (byte) 0x41 };
    public static final int HEADER_SIZE = 7;

    /** Version 1: LTPAToken2 with signature and encryption algorithm header. */
    public static final byte HEADER_VERSION_1 = (byte) 0x01;

    public static final byte SIG_ALG_SHA1_RSA = (byte) 0x01;
    public static final byte SIG_ALG_SHA512_RSA = (byte) 0x02;
    public static final byte SIG_ALG_ML_DSA = (byte) 0x03;
    public static final byte SIG_ALG_HYBRID_SHA1_RSA_ML_DSA = (byte) 0x04;
    public static final byte SIG_ALG_HYBRID_SHA512_RSA_ML_DSA = (byte) 0x05;

    public static final String SIG_ALG_NAME_HYBRID_SHA1_RSA_ML_DSA = "HYBRID-SHA1withRSA-ML-DSA";
    public static final String SIG_ALG_NAME_HYBRID_SHA512_RSA_ML_DSA = "HYBRID-SHA512withRSA-ML-DSA";

    public static final byte ENC_ALG_AES_CBC_128 = (byte) 0x01;
    public static final byte ENC_ALG_AES_CBC_256 = (byte) 0x02;
    public static final byte ENC_ALG_AES_GCM_256 = (byte) 0x03;

    private LTPATokenHeader() {}

    /**
     * Returns {@code true} if {@code tokenBytes} starts with {@link #HEADER_MAGIC}.
     * returns {@code false} if the array is shorter than 4 bytes.
     */
    public static boolean hasMagic(byte[] tokenBytes) {
        if (tokenBytes == null || tokenBytes.length < HEADER_SIZE) {
            return false;
        }
        return tokenBytes[0] == HEADER_MAGIC[0]
            && tokenBytes[1] == HEADER_MAGIC[1]
            && tokenBytes[2] == HEADER_MAGIC[2]
            && tokenBytes[3] == HEADER_MAGIC[3];
    }

    /**
     * Derives the {@code SigAlg} header byte from the ltpa signing configuration
     *
     * @param signingMode      "pqc", "classical"
     * @param classicalSigAlg  JCA algorithm string (e.g. "SHA1withRSA", "SHA512withRSA") — must not be null
     * @return the SigAlg header byte
     * @throws IllegalArgumentException if the combination is unrecognised
     */
    public static byte encodeSigAlg(String signingMode, String classicalSigAlg) {
        if ("pqc".equals(signingMode)) {
            return SIG_ALG_ML_DSA; // maybe look at specifying mldsa variant?
        }
        if ("hybrid".equals(signingMode)) {
            if (CryptoUtils.SIGNATURE_ALGORITHM_SHA512WITHRSA.equals(classicalSigAlg)) {
                return SIG_ALG_HYBRID_SHA512_RSA_ML_DSA;
            }
            if (CryptoUtils.SIGNATURE_ALGORITHM_SHA1WITHRSA.equals(classicalSigAlg)) {
                return SIG_ALG_HYBRID_SHA1_RSA_ML_DSA;
            }
            throw new IllegalArgumentException("Unrecognised classicalSigAlg for hybrid header encoding: " + classicalSigAlg);
        }
        if (CryptoUtils.SIGNATURE_ALGORITHM_SHA1WITHRSA.equals(classicalSigAlg)) {
            return SIG_ALG_SHA1_RSA;
        }
        if (CryptoUtils.SIGNATURE_ALGORITHM_SHA512WITHRSA.equals(classicalSigAlg)) {
            return SIG_ALG_SHA512_RSA;
        }
        throw new IllegalArgumentException("Unrecognised classicalSigAlg for header encoding: " + classicalSigAlg);
    }

    /**
     * Derives the {@code EncAlg} header byte from the token's encryption configuration.
     *
     * @param resolvedCipher    JCA cipher string (e.g. "AES/GCM/NoPadding"), or null
     * @param resolvedKeyLength AES key length in bytes (16 or 32), or 0 for FIPS-aware default
     * @return the EncAlg header byte
     * @throws IllegalArgumentException if the combination is unrecognised
     */
    public static byte encodeEncAlg(String resolvedCipher, int resolvedKeyLength) {
        if (CryptoUtils.AES_GCM_CIPHER.equals(resolvedCipher)) {
            return ENC_ALG_AES_GCM_256;
        }
        // CBC — key length distinguishes 128 vs 256; 0 means use FIPS-aware default
        int keyLen = (resolvedKeyLength > 0) ? resolvedKeyLength
                   : (CryptoUtils.isFips140_3Enabled() ? CryptoUtils.AES_256_KEY_LENGTH_BYTES
                                                        : CryptoUtils.AES_128_KEY_LENGTH_BYTES);
        if (keyLen == CryptoUtils.AES_128_KEY_LENGTH_BYTES) {
            return ENC_ALG_AES_CBC_128;
        }
        if (keyLen == CryptoUtils.AES_256_KEY_LENGTH_BYTES) {
            return ENC_ALG_AES_CBC_256;
        }
        throw new IllegalArgumentException("Unrecognised resolvedKeyLength for header encoding: " + resolvedKeyLength);
    }

    /**
     * Resolves the JCA signature algorithm string from a {@code SigAlg} header byte.
     *
     * @param sigAlgByte the SigAlg byte read from the token header
     * @return the JCA algorithm string (e.g. "SHA512withRSA")
     * @throws InvalidTokenException if the byte value is unknown
     */
    public static String decodeSigAlg(byte sigAlgByte) throws InvalidTokenException {
        switch (sigAlgByte) {
            case SIG_ALG_SHA1_RSA: return CryptoUtils.SIGNATURE_ALGORITHM_SHA1WITHRSA;
            case SIG_ALG_SHA512_RSA: return CryptoUtils.SIGNATURE_ALGORITHM_SHA512WITHRSA;
            case SIG_ALG_ML_DSA: return "ML-DSA";
            case SIG_ALG_HYBRID_SHA1_RSA_ML_DSA: return SIG_ALG_NAME_HYBRID_SHA1_RSA_ML_DSA;
            case SIG_ALG_HYBRID_SHA512_RSA_ML_DSA: return SIG_ALG_NAME_HYBRID_SHA512_RSA_ML_DSA;
            default:
                throw new InvalidTokenException("Unknown SigAlg byte in token header: 0x"
                        + Integer.toHexString(sigAlgByte & 0xFF));
        }
    }

    /**
     * Checks if the given SigAlg header byte represents a hybrid signature algorithm.
     */
    public static boolean isHybridSigAlg(byte sigAlgByte) {
        return sigAlgByte == SIG_ALG_HYBRID_SHA1_RSA_ML_DSA || sigAlgByte == SIG_ALG_HYBRID_SHA512_RSA_ML_DSA;
    }

    /**
     * Checks if the given decoded signature algorithm string represents a hybrid signature algorithm.
     */
    public static boolean isHybridSigAlg(String sigAlg) {
        return SIG_ALG_NAME_HYBRID_SHA1_RSA_ML_DSA.equals(sigAlg) || SIG_ALG_NAME_HYBRID_SHA512_RSA_ML_DSA.equals(sigAlg);
    }

    /**
     * Extracts the underlying classical signature algorithm from a hybrid signature algorithm name.
     */
    public static String getClassicalSigAlgFromHybrid(String hybridSigAlg) {
        if (SIG_ALG_NAME_HYBRID_SHA512_RSA_ML_DSA.equals(hybridSigAlg)) {
            return CryptoUtils.SIGNATURE_ALGORITHM_SHA512WITHRSA;
        }
        return CryptoUtils.SIGNATURE_ALGORITHM_SHA1WITHRSA;
    }

    /**
     * Resolves the JCA cipher string from an {@code EncAlg} header byte.
     *
     * @param encAlgByte the EncAlg byte read from the token header
     * @return the JCA cipher string (e.g. "AES/GCM/NoPadding")
     * @throws InvalidTokenException if the byte value is unknown
     */
    public static String decodeCipher(byte encAlgByte) throws InvalidTokenException {
        switch (encAlgByte) {
            case ENC_ALG_AES_CBC_128: return CryptoUtils.AES_CBC_CIPHER;
            case ENC_ALG_AES_CBC_256: return CryptoUtils.AES_CBC_CIPHER;
            case ENC_ALG_AES_GCM_256: return CryptoUtils.AES_GCM_CIPHER;
            default:
                throw new InvalidTokenException("Unknown EncAlg byte in token header: 0x"
                        + Integer.toHexString(encAlgByte & 0xFF));
        }
    }

    /**
     * Resolves the AES key length in bytes from an {@code EncAlg} header byte.
     *
     * @param encAlgByte the EncAlg byte read from the token header
     * @return key length in bytes (16 or 32); 0 for GCM (key length is implicit)
     * @throws InvalidTokenException if the byte value is unknown
     */
    public static int decodeKeyLength(byte encAlgByte) throws InvalidTokenException {
        switch (encAlgByte) {
            case ENC_ALG_AES_CBC_128: return CryptoUtils.AES_128_KEY_LENGTH_BYTES;
            case ENC_ALG_AES_CBC_256: return CryptoUtils.AES_256_KEY_LENGTH_BYTES;
            case ENC_ALG_AES_GCM_256: return 0;
            default:
                throw new InvalidTokenException("Unknown EncAlg byte in token header: 0x"
                        + Integer.toHexString(encAlgByte & 0xFF));
        }
    }
}
