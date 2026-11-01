/*******************************************************************************
 * Copyright (c) 2004, 2026 IBM Corporation and others.
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

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;

import javax.crypto.BadPaddingException;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.websphere.security.auth.InvalidTokenException;
import com.ibm.websphere.security.auth.TokenExpiredException;
import com.ibm.ws.common.crypto.CryptoUtils;
import com.ibm.ws.common.encoder.Base64Coder;
import com.ibm.ws.crypto.ltpakeyutil.LTPAKeyUtil;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPublicKey;
import com.ibm.ws.ffdc.annotation.FFDCIgnore;
import com.ibm.ws.security.token.ltpa.pqc.PQCConstants;
import com.ibm.ws.security.token.ltpa.pqc.PQCSignatureHelper;
import com.ibm.wsspi.security.ltpa.Token;
import com.ibm.wsspi.security.token.AttributeNameConstants;

/**
 * Represents an LTPAToken that is delegatable. The token contains user data,
 * expiration time, along with the digital signature based on the data and the RSA key.
 */
public class LTPAToken2 implements Token, Serializable {

    private static final boolean fipsEnabled = CryptoUtils.isFips140_3Enabled();

    private static final TraceComponent tc = Tr.register(LTPAToken2.class);

    private static final long serialVersionUID = 1L;
    private static final String DELIM = "%";
    private static final MessageDigest md1JCE;
    private static final MessageDigest md2JCE;
    private static final Object lockObj1;
    private static final Object lockObj2;

    private final short version = 1;
    private byte signature[];
    private byte[] encryptedBytes = null;
    private UserData userData;
    private long expirationInMilliseconds;
    private final byte[] sharedKey;
    private final LTPAPrivateKey privateKey;
    private final LTPAPublicKey publicKey;
   
    // PQC: ML-DSA keys (Issue #35556 - Task 2.7)
    private final PrivateKey mldsaPrivateKey;
    private final PublicKey mldsaPublicKey;
    private final String signingMode;
    private final String classicalSigAlg;
    private final String resolvedCipher;
    private final int resolvedKeyLength;
    private String sigAlgForVerify = null;
    private String headerCipher = null;
    private int headerKeyLen = 0;

    private long expirationDifferenceAllowed;

    static {
        MessageDigest m1 = null, m2 = null;

        m1 = CryptoUtils.getMessageDigestForLTPA();
        m2 = CryptoUtils.getMessageDigestForLTPA();

        md1JCE = m1;
        md2JCE = m2;
        lockObj1 = new Object();
        lockObj2 = new Object();
    }

    /**
     * An LTPA2 token constructor.
     *
     * @param tokenBytes The byte representation of the LTPA2 token
     * @param sharedKey  The LTPA shared key
     * @param privateKey The LTPA private key
     * @param publicKey  The LTPA public key
     * @param attributes The list of attributes will be removed from the LTPA2 token
     */
     public LTPAToken2(byte[] tokenBytes, @Sensitive byte[] sharedKey, LTPAPrivateKey privateKey, LTPAPublicKey publicKey, long expDiffAllowed,
                        String... attributes) throws InvalidTokenException, TokenExpiredException {
        this(tokenBytes, sharedKey, privateKey, publicKey, null, null, PQCConstants.CRYPTO_MODE_CLASSICAL, expDiffAllowed, attributes);
     }

    public LTPAToken2(byte[] tokenBytes, @Sensitive byte[] sharedKey, LTPAPrivateKey privateKey, LTPAPublicKey publicKey,
                      PrivateKey mldsaPrivateKey, PublicKey mldsaPublicKey, String signingMode, long expDiffAllowed,
                      String... attributes) throws InvalidTokenException, TokenExpiredException {
        checkTokenBytes(tokenBytes);
        this.signature = null;
        this.encryptedBytes = tokenBytes.clone();
        this.sharedKey = sharedKey.clone();
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.mldsaPrivateKey = mldsaPrivateKey;
        this.mldsaPublicKey = mldsaPublicKey;
        this.signingMode = signingMode;
        this.classicalSigAlg = null; // not used on validation path
        this.resolvedCipher = null;  // not used on validation path
        this.resolvedKeyLength = 0;  // not used on validation path
        this.expirationInMilliseconds = 0;
        this.expirationDifferenceAllowed = expDiffAllowed;
        extractTokenHeader();
        decrypt();
        isValid();
        if (attributes != null) {
            //Reset signature, encryptedBytes and remove attributes
            this.signature = null;
            this.encryptedBytes = null;
            userData.removeAttributes(attributes);
        }
    }

    /**
     * An LTPA2 token constructor.
     *
     * @param tokenBytes The byte representation of the LTPA2 token
     * @param sharedKey  The LTPA shared key
     * @param privateKey The LTPA private key
     * @param publicKey  The LTPA public key
     */

    protected LTPAToken2(String accessID, long expirationInMinutes, @Sensitive byte[] sharedKey,
                         LTPAPrivateKey privateKey, LTPAPublicKey publicKey) {
        this(accessID, expirationInMinutes, sharedKey, privateKey, publicKey, null, null, "classical", null, null, 0);
    }

    protected LTPAToken2(String accessID, long expirationInMinutes, @Sensitive byte[] sharedKey,
                         LTPAPrivateKey privateKey, LTPAPublicKey publicKey,
                         PrivateKey mldsaPrivateKey, PublicKey mldsaPublicKey, String signingMode) {
        this(accessID, expirationInMinutes, sharedKey, privateKey, publicKey, mldsaPrivateKey, mldsaPublicKey, signingMode, null, null, 0);
    }

    protected LTPAToken2(String accessID, long expirationInMinutes, @Sensitive byte[] sharedKey,
                         LTPAPrivateKey privateKey, LTPAPublicKey publicKey,
                         PrivateKey mldsaPrivateKey, PublicKey mldsaPublicKey, String signingMode, String classicalSigAlg,
                         String resolvedCipher, int resolvedKeyLength) {
        this.signature = null;
        this.encryptedBytes = null;
        this.sharedKey = sharedKey.clone();
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.mldsaPrivateKey = mldsaPrivateKey;
        this.mldsaPublicKey = mldsaPublicKey;
        this.signingMode = signingMode;
        this.classicalSigAlg = classicalSigAlg;
        this.resolvedCipher = resolvedCipher;
        this.resolvedKeyLength = resolvedKeyLength;
        this.userData = new UserData(accessID);
        setExpiration(expirationInMinutes);
    }

    /**
     * An LTPA2 token constructor (Used for the clone).
     *
     * @param expirationInMinutes Expiration limit of the LTPA2 token in minutes
     * @param sharedKey           The LTPA shared key
     * @param privateKey          The LTPA private key
     * @param publicKey           The LTPA public key
     * @param userdata            The UserData
     */
    protected LTPAToken2(long expirationInMinutes, @Sensitive byte[] sharedKey, LTPAPrivateKey privateKey, LTPAPublicKey publicKey, UserData userdata) {
        this.signature = null;
        this.encryptedBytes = null;
        this.sharedKey = sharedKey.clone();
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.mldsaPrivateKey = null;
        this.mldsaPublicKey = null;
        this.signingMode = "classical";
        this.classicalSigAlg = null;
        this.resolvedCipher = null;
        this.resolvedKeyLength = 0;
        this.userData = userdata;
        setExpiration(expirationInMinutes);
    }

    /**
     * Encrypt the token. The cipher is selected directly from {@code encryptionAlg}:
     * <ul>
     *   <li>{@code AES-GCM-256} → {@link LTPAKeyUtil#encryptGCM}</li>
     *   <li>{@code AES-CBC-256} or {@code AES-CBC-128} → {@link LTPAKeyUtil#encrypt} with AES/CBC/PKCS5Padding</li>
     * </ul>
     *
     * @throws Exception
     */
    private final void encrypt() throws Exception {
        long startEncrypt = System.currentTimeMillis();
        System.out.println("[LTPAToken2] encrypt: start; cipher=" + resolvedCipher
                + ", keyLen=" + resolvedKeyLength + "; time=" + startEncrypt + " ms");

        String signStr = Base64Coder.toString(Base64Coder.base64Encode(signature));
        String ud = userData.toString();

        // Build the Token2 inner plaintext: accessID % expiration % base64(signature)
        byte[] accessID = Base64Coder.getBytes(ud);
        StringBuilder sb = new StringBuilder(DELIM);
        sb.append(getExpiration()).append(DELIM).append(signStr);
        byte[] timeAndSign = getSimpleBytes(sb.toString());
        byte[] toBeEnc = new byte[accessID.length + timeAndSign.length];
        for (int i = 0; i < accessID.length; i++) {
            toBeEnc[i] = accessID[i];
        }
        for (int i = accessID.length; i < toBeEnc.length; i++) {
            toBeEnc[i] = timeAndSign[i - accessID.length];
        }

        if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
            Tr.event(this, tc, "resolvedCipher=" + resolvedCipher + " resolvedKeyLength=" + resolvedKeyLength);
        }

        long startCipher = System.currentTimeMillis();
        byte[] ciphertext;
        try {
            if (CryptoUtils.AES_GCM_CIPHER.equals(resolvedCipher)) {
                ciphertext = LTPAKeyUtil.encryptGCM(toBeEnc, sharedKey);
            } else {
                // resolvedCipher is AES/CBC/PKCS5Padding; resolvedKeyLength is 16 or 32 (0 = FIPS-aware default)
                ciphertext = LTPAKeyUtil.encrypt(toBeEnc, sharedKey, resolvedCipher, resolvedKeyLength);
            }
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Error encrypting; " + e);
            }
            throw e;
        }
        long cipherMs = System.currentTimeMillis() - startCipher;
        System.out.println("[LTPAToken2] encrypt: cipher (" + resolvedCipher + ", keyLen=" + resolvedKeyLength + ") took " + cipherMs + " ms"
                + "; plaintext=" + toBeEnc.length + " bytes, ciphertext=" + ciphertext.length + " bytes");

        // Write token header
        long startHeader = System.currentTimeMillis();
        byte sigAlgByte = LTPATokenHeader.encodeSigAlg(signingMode, classicalSigAlg);
        byte encAlgByte = LTPATokenHeader.encodeEncAlg(resolvedCipher, resolvedKeyLength);
        encryptedBytes = new byte[LTPATokenHeader.HEADER_SIZE + ciphertext.length];
        System.arraycopy(LTPATokenHeader.HEADER_MAGIC, 0, encryptedBytes, 0, LTPATokenHeader.HEADER_MAGIC.length);
        encryptedBytes[4] = LTPATokenHeader.HEADER_VERSION_1;
        encryptedBytes[5] = sigAlgByte;
        encryptedBytes[6] = encAlgByte;
        System.arraycopy(ciphertext, 0, encryptedBytes, LTPATokenHeader.HEADER_SIZE, ciphertext.length);
        long headerMs = System.currentTimeMillis() - startHeader;
        System.out.println("[LTPAToken2] encrypt: header written;"
                + " magic=LTPA, version=0x01"
                + ", sigAlgByte=0x" + Integer.toHexString(sigAlgByte & 0xFF) + " (" + signingMode + "/" + classicalSigAlg + ")"
                + ", encAlgByte=0x" + Integer.toHexString(encAlgByte & 0xFF) + " (" + resolvedCipher + ", keyLen=" + resolvedKeyLength + ")"
                + ", headerSize=" + LTPATokenHeader.HEADER_SIZE + " bytes, took=" + headerMs + " ms");

        long totalMs = System.currentTimeMillis() - startEncrypt;
        System.out.println("[LTPAToken2] encrypt: end; tokenSize=" + encryptedBytes.length + " bytes, total=" + totalMs + " ms");

        if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
            Tr.event(this, tc, "Encrypted bytes are: " + (encryptedBytes == null ? "" : Base64Coder.toString(Base64Coder.base64Encode(encryptedBytes))));
        }
    }

    /**
     * Extracts and validates the LTPA2 token header from {@link #encryptedBytes}.
     *
     * @throws InvalidTokenException if the magic prefix is present but the version
     *                               byte is not recognised.
     */
    private void extractTokenHeader() throws InvalidTokenException {
        long startHeader = System.currentTimeMillis();
        if (!LTPATokenHeader.hasMagic(encryptedBytes)) {
            System.out.println("[LTPAToken2] extractTokenHeader: no magic prefix found — legacy token (no header)");
            return;
        }
        byte versionByte = encryptedBytes[4];
        if (versionByte != LTPATokenHeader.HEADER_VERSION_1) {
            throw new InvalidTokenException("Unknown token header version: 0x"
                    + Integer.toHexString(versionByte & 0xFF));
        }
        sigAlgForVerify = LTPATokenHeader.decodeSigAlg(encryptedBytes[5]);
        headerCipher = LTPATokenHeader.decodeCipher(encryptedBytes[6]);
        headerKeyLen = LTPATokenHeader.decodeKeyLength(encryptedBytes[6]);
        long headerMs = System.currentTimeMillis() - startHeader;
        System.out.println("[LTPAToken2] extractTokenHeader: header parsed;"
                + " version=0x" + Integer.toHexString(versionByte & 0xFF)
                + ", sigAlgByte=0x" + Integer.toHexString(encryptedBytes[5] & 0xFF) + " -> sigAlgForVerify=" + sigAlgForVerify
                + ", encAlgByte=0x" + Integer.toHexString(encryptedBytes[6] & 0xFF) + " -> cipher=" + headerCipher + ", keyLen=" + headerKeyLen
                + ", took=" + headerMs + " ms");
    }

    /**
     * Decrypt the encrypted token bytes passed into the constructor.
     * Relies on {@link #extractTokenHeader()} having been called first to populate
     * {@link #headerCipher} and {@link #headerKeyLen} for headered tokens.
     */
    @FFDCIgnore({ BadPaddingException.class, Exception.class })
    private final void decrypt() throws InvalidTokenException {
        long startDecrypt = System.currentTimeMillis();
        System.out.println("[LTPAToken2] decrypt: start; headerCipher=" + headerCipher
                + ", headerKeyLen=" + headerKeyLen + "; time=" + startDecrypt + " ms");

        byte[] tokenData;
        try {
            if (headerCipher != null) {
                byte[] ciphertext = Arrays.copyOfRange(encryptedBytes, LTPATokenHeader.HEADER_SIZE, encryptedBytes.length);

                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(this, tc, "decrypt: headered token cipher=" + headerCipher + " keyLen=" + headerKeyLen);
                }

                long startCipher = System.currentTimeMillis();
                if (CryptoUtils.AES_GCM_CIPHER.equals(headerCipher)) {
                    tokenData = LTPAKeyUtil.decryptGCM(ciphertext, sharedKey);
                } else {
                    tokenData = LTPAKeyUtil.decrypt(ciphertext, sharedKey, headerCipher, headerKeyLen);
                }
                long cipherMs = System.currentTimeMillis() - startCipher;
                System.out.println("[LTPAToken2] decrypt: cipher (" + headerCipher + ", keyLen=" + headerKeyLen + ") took " + cipherMs + " ms"
                        + "; ciphertext=" + ciphertext.length + " bytes, plaintext=" + tokenData.length + " bytes");

            } else {
                // ---- Legacy token path ----
                // Pre-branch tokens are always one of two fixed cipher+sig pairs coupled to FIPS mode.
                // Try pairs in FIPS-preference order; use parseToken() as discriminator because
                // CBC with the wrong key size yields silent garbage rather than throwing.
                int primaryKeyLen  = fipsEnabled ? CryptoUtils.AES_256_KEY_LENGTH_BYTES : CryptoUtils.AES_128_KEY_LENGTH_BYTES;
                int fallbackKeyLen = fipsEnabled ? CryptoUtils.AES_128_KEY_LENGTH_BYTES : CryptoUtils.AES_256_KEY_LENGTH_BYTES;
                String primarySigAlg  = fipsEnabled ? CryptoUtils.SIGNATURE_ALGORITHM_SHA512WITHRSA : CryptoUtils.SIGNATURE_ALGORITHM_SHA1WITHRSA;
                String fallbackSigAlg = fipsEnabled ? CryptoUtils.SIGNATURE_ALGORITHM_SHA1WITHRSA : CryptoUtils.SIGNATURE_ALGORITHM_SHA512WITHRSA;

                tokenData = decryptLegacyCBC(primaryKeyLen, primarySigAlg, fallbackKeyLen, fallbackSigAlg);
            }

            checkTokenBytes(tokenData);
            String UTF8TokenString = toUTF8String(tokenData);
            String[] userFields = LTPATokenizer.parseToken(UTF8TokenString);
            Map<String, ArrayList<String>> attribs = LTPATokenizer.parseUserData(userFields[0]);
            userData = new UserData(attribs);

            String tokenString = toSimpleString(tokenData);
            String[] fields = LTPATokenizer.parseToken(tokenString);
            String[] expirationArray = userData.getAttributes(AttributeNameConstants.WSTOKEN_EXPIRATION);
            if (expirationArray != null && expirationArray[expirationArray.length - 1] != null) {
                // the new expiration value inside the signature for LTPAToken2
                expirationInMilliseconds = Long.parseLong(expirationArray[expirationArray.length - 1]);

                // Liberty and Traditional WebSphere both create LTPA Tokens with 3 fields. (userData % expiration % sign)
                // Normally, the expiration value is read from the first field of the token, the userData field.
                // The expiration value may be read from the second field of the token instead, to maintain legacy support in Traditional WebSphere.

                // If the LTPAToken contains both expiration formats, Compare the values to ensure they are within the expiration difference allowed.
                // If the difference between the two expiration values is greater than expirationDifferenceAllowed, then an InvalidTokenException will be thrown.
                // If expirationDifferenceAllowed is 0, then the two expiration values must match.
                // If expirationDifferenceAllowed is less than 0, then the two expiration values are not compared.
                // expirationDifferenceAllowed is 3 seconds (3000ms) by default.
                if (fields.length == 3 && expirationDifferenceAllowed >= 0 && (Math.abs(expirationInMilliseconds - Long.parseLong(fields[1])) > expirationDifferenceAllowed)) {
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(this, tc, "Token validation failed due to the expiration fields having a difference greater than: "
                                           + expirationDifferenceAllowed + " milliseconds\n"
                                           + "first field expiration: " + expirationInMilliseconds + " milliseconds\n"
                                           + "second field expiration: " + fields[1] + " milliseconds");
                    }
                    throw new InvalidTokenException("Token Validation Failed");
                }
            } else {
                // the old expiration value outside of the signature for LTPAToken
                expirationInMilliseconds = Long.parseLong(fields[1]);
            }
            // the signature will always be the last field, but the fields array length may be 2 or 3.
            byte[] signature = Base64Coder.base64Decode(Base64Coder.getBytes(fields[fields.length - 1]));
            setSignature(signature);

            long totalMs = System.currentTimeMillis() - startDecrypt;
            System.out.println("[LTPAToken2] decrypt: end; sigAlgForVerify=" + sigAlgForVerify
                    + ", tokenData=" + tokenData.length + " bytes, total=" + totalMs + " ms");
        } catch (BadPaddingException e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Caught BadPaddingException while decrypting token, this is only a critical problem if decryption should have worked.", e);
            }
            throw new InvalidTokenException(e.getMessage(), e);
        } catch (InvalidTokenException e) {
            throw e;
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Error decrypting; " + e);
            }
            throw new InvalidTokenException(e.getMessage(), e);
        }
    }

    /**
     * Legacy CBC probe: tries two AES-CBC key lengths in order.
     * Uses {@link LTPATokenizer#parseToken} as the discriminator because CBC with
     * the wrong key size decrypts silently to garbage rather than throwing.
     * Sets {@link #sigAlgForVerify} from whichever pair produces parseable plaintext.
     */
    @FFDCIgnore(Exception.class)
    private byte[] decryptLegacyCBC(int primaryKeyLen, String primarySigAlg,
                                     int fallbackKeyLen, String fallbackSigAlg) throws Exception {
        byte[] candidate = LTPAKeyUtil.decrypt(encryptedBytes.clone(), sharedKey, CryptoUtils.AES_CBC_CIPHER, primaryKeyLen);
        try {
            LTPATokenizer.parseToken(toSimpleString(candidate));
            sigAlgForVerify = primarySigAlg;
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(this, tc, "decrypt: legacy CBC-" + (primaryKeyLen * 8) + " succeeded");
            }
            return candidate;
        } catch (Exception parseEx) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(this, tc, "decrypt: legacy CBC-" + (primaryKeyLen * 8) + " parse failed, trying CBC-" + (fallbackKeyLen * 8));
            }
        }
        byte[] fallback = LTPAKeyUtil.decrypt(encryptedBytes.clone(), sharedKey, CryptoUtils.AES_CBC_CIPHER, fallbackKeyLen);
        sigAlgForVerify = fallbackSigAlg;
        return fallback;
    }

    /**
     * Sign the token passed into the token.
     */
    private final void sign() throws Exception {
        long startSign = System.currentTimeMillis();
        String effectiveSigAlg = "pqc".equals(signingMode)
                ? (mldsaPrivateKey != null ? mldsaPrivateKey.getAlgorithm() : "ML-DSA")
                : (classicalSigAlg != null ? classicalSigAlg : signatureAlgorithmLabel());
        System.out.println("[LTPAToken2] sign: start; signingMode=" + signingMode
                + ", sigAlg=" + effectiveSigAlg + "; time=" + startSign + " ms");

        String dataStr = this.getUserData().toString();
        byte[] data = Base64Coder.getBytes(dataStr);

        byte[] signature;
        if ("pqc".equals(signingMode)) {
            signature = PQCSignatureHelper.signMLDSA(data, mldsaPrivateKey, null);
        } else {
            signature = sign(data, this.privateKey);
        }

        this.setSignature(signature);

        long totalMs = System.currentTimeMillis() - startSign;
        System.out.println("[LTPAToken2] sign: end; signingMode=" + signingMode
                + ", sigAlg=" + effectiveSigAlg
                + ", sigLen=" + (signature != null ? signature.length : 0) + " bytes, total=" + totalMs + " ms");
    }


    private final byte[] sign(byte[] msg, LTPAPrivateKey privKey) throws Exception {
        long startRsaSign = System.currentTimeMillis();
        System.out.println("[LTPAToken2] sign (RSA/" + (classicalSigAlg != null ? classicalSigAlg : signatureAlgorithmLabel()) + "): start; msgLen=" + msg.length + " bytes");

        byte[] data;
        synchronized (lockObj1) {
            data = md1JCE.digest(msg);
        }
        byte[][] rsaPrivKey = LTPAKeyUtil.getRawKey(privKey);
        LTPAKeyUtil.setRSAKey(rsaPrivKey);
        byte[] signature = LTPAKeyUtil.signISO9796(rsaPrivKey, data, 0, data.length);

        long rsaSignMs = System.currentTimeMillis() - startRsaSign;
        System.out.println("[LTPAToken2] sign (RSA): end; sigLen=" + signature.length + " bytes, total=" + rsaSignMs + " ms");
        return signature;
    }

    private static String signatureAlgorithmLabel() {
        return CryptoUtils.getSignatureAlgorithm();
    }

    /**
     * Verify the token.
     */
    private final boolean verify() throws Exception {
        long startVerify = System.currentTimeMillis();
        System.out.println("[LTPAToken2] verify: start; sigAlgForVerify=" + sigAlgForVerify + "; time=" + startVerify + " ms");

        String dataStr = this.getUserData().toString();
        byte[] data = Base64Coder.getBytes(dataStr);

        boolean result;
        if ("ML-DSA".equals(sigAlgForVerify)) {
            result = PQCSignatureHelper.verifyMLDSA(data, signature, mldsaPublicKey, null);
        } else {
            result = verify(data, signature, publicKey);
        }

        long totalMs = System.currentTimeMillis() - startVerify;
        System.out.println("[LTPAToken2] verify: end; sigAlgForVerify=" + sigAlgForVerify
                + ", valid=" + result + ", total=" + totalMs + " ms");
        return result;
    }

    private final boolean verify(byte[] msg, byte[] signature, LTPAPublicKey pubKey) throws Exception {
        if (msg == null) {
            throw new IllegalArgumentException("null message");
        } else if (signature == null) {
            throw new IllegalArgumentException("null signature");
        }

        long startRsaVerify = System.currentTimeMillis();
        System.out.println("[LTPAToken2] verify (RSA/" + sigAlgForVerify + "): start; msgLen=" + msg.length + " bytes, sigLen=" + signature.length + " bytes");

        byte[] data;
        synchronized (lockObj2) {
            data = md2JCE.digest(msg);
        }

        // sigAlgForVerify is always set by decrypt() before verify() is called —
        // either from the token header or from the legacy CBC pair probe.
        // Use it directly: one algorithm, one verify call, no fallback loop.
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(this, tc, "verify: using sigAlg=" + sigAlgForVerify);
        }
        byte[][] rsaPubKey = LTPAKeyUtil.getRawKey(pubKey);
        boolean valid = LTPAKeyUtil.verifyISO9796(rsaPubKey, data, 0, data.length, signature, 0, signature.length);

        long rsaVerifyMs = System.currentTimeMillis() - startRsaVerify;
        System.out.println("[LTPAToken2] verify (RSA/" + sigAlgForVerify + "): end; valid=" + valid + ", total=" + rsaVerifyMs + " ms");
        return valid;
    }

    /** {@inheritDoc} */
    @Override
    @FFDCIgnore(Exception.class)
    public final boolean isValid() throws InvalidTokenException, TokenExpiredException {
        boolean verified = false;

        try {
            verified = verify();
        } catch (Exception e) {
            verified = false;
            throw new InvalidTokenException(e.getMessage(), e);
        }

        if (!verified) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(this, tc, "Invalid signature of the token " + this);
            }
            throw new InvalidTokenException("Token Validation Failed");
        }

        validateExpiration();

        return verified;
    }

    /**
     * Checks if the token has expired.
     *
     * @throws TokenExpiredException
     */
    public final void validateExpiration() throws TokenExpiredException {
        Date d = new Date();
        Date expD = new Date(getExpiration());
        boolean expired = d.after(expD);
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(this, tc, "Current time = " + d + ", expiration time = " + expD);
        }
        if (expired) {
            String msg = "The token has expired: current time = \"" + d + "\", expire time = \"" + expD + "\"";
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(this, tc, msg);
            }
            throw new TokenExpiredException(expirationInMilliseconds, msg);
        }
    }

    /** {@inheritDoc} */
    @Override
    @FFDCIgnore(Exception.class)
    public final byte[] getBytes() throws InvalidTokenException, TokenExpiredException {
        if (encryptedBytes == null) {
            try {
                sign();
                encrypt();
            } catch (Exception e) {
                throw new com.ibm.websphere.security.auth.InvalidTokenException(e.getMessage(), e);
            }
        }
        return encryptedBytes.clone();
    }

    /** {@inheritDoc} */
    @Override
    public final long getExpiration() {
        return expirationInMilliseconds;
    }

    /** {@inheritDoc} */
    @Override
    public final short getVersion() {
        return version;
    }

    /** {@inheritDoc} */
    @Override
    public final String[] addAttribute(String name, String value) {
        signature = null;
        encryptedBytes = null;
        return userData.addAttribute(name, value);
    }

    /** {@inheritDoc} */
    @Override
    public final String[] getAttributes(String name) {
        return userData.getAttributes(name);
    }

    /** {@inheritDoc} */
    @Override
    public final Enumeration<String> getAttributeNames() {
        return userData.getAttributeNames();
    }

    @Override
    public final String toString() {
        return encryptedBytes == null ? "NULL" : Base64Coder.base64EncodeToString(encryptedBytes);
    }

    /**
     * Make a deep copy of the LTPA2 token when necessary
     *
     * @return Object A new copy of the LTPA2 token
     */
    @Override
    public final Object clone() {
        UserData userdata = (UserData) userData.clone();
        return new LTPAToken2(getExpiration(), sharedKey, privateKey, publicKey, userdata);
    }

    /**
     * Check the byte expression of the LTPA2 token
     *
     * @param tokenBytes The byte expression of the LTPA2 token
     */
    private static final void checkTokenBytes(byte[] tokenBytes) {
        if ((tokenBytes == null) || (tokenBytes.length == 0)) {
            throw new IllegalArgumentException("No token bytes specified");
        }
    }

    /**
     * Set a new signature of the LTPA2 token
     *
     * @param newValue The signature of the LTPA2 token
     */
    private final void setSignature(byte newValue[]) {
        this.signature = newValue;
    }

    /**
     * Get the UserData
     *
     * @return The UserData
     */
    private final UserData getUserData() {
        return userData;
    }

    /**
     * Set expiration limit of the LTPA2 token
     *
     * @param expirationInMinutes the expiration limit of the LTPA2 token in minutes
     */
    private final void setExpiration(long expirationInMinutes) {
        expirationInMilliseconds = System.currentTimeMillis() + expirationInMinutes * 60 * 1000;
        signature = null;
        if (userData != null) {
            encryptedBytes = null;
            userData.addAttribute("expire", Long.toString(expirationInMilliseconds));
        } else {
            encryptedBytes = null;
        }
    }

    /**
     * Convert the byte representation to the UTF-8 String form.
     *
     * @param b The byte representation
     * @return The UTF-8 String form
     */
    private static final String toUTF8String(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    /**
     * Convert the byte representation to the String form.
     *
     * @param b The byte representation
     * @return The String form
     */
    private static final String toSimpleString(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0, len = b.length; i < len; i++) {
            sb.append((char) (b[i] & 0xff));
        }
        String str = sb.toString();
        return str;
    }

    /**
     * Convert the String form to the byte representation
     *
     * @param str The String form
     * @return The byte representation
     */
    private static final byte[] getSimpleBytes(String str) {
        StringBuilder sb = new StringBuilder(str);
        byte[] b = new byte[sb.length()];
        for (int i = 0, len = sb.length(); i < len; i++) {
            b[i] = (byte) sb.charAt(i);
        }
        return b;
    }

}
