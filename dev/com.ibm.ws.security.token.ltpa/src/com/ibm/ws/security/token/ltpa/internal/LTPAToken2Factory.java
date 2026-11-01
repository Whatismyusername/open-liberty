/*******************************************************************************
 * Copyright (c) 2004, 2025 IBM Corporation and others.
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

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.websphere.security.auth.InvalidTokenException;
import com.ibm.websphere.security.auth.TokenCreationFailedException;
import com.ibm.websphere.security.auth.TokenExpiredException;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPublicKey;
import com.ibm.ws.ffdc.annotation.FFDCIgnore;
import com.ibm.ws.security.token.ltpa.LTPAKeyInfoManager;
import com.ibm.ws.security.token.ltpa.LTPAValidationKeysInfo;
import com.ibm.wsspi.security.ltpa.Token;
import com.ibm.wsspi.security.ltpa.TokenFactory;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class LTPAToken2Factory implements TokenFactory {
    private static final TraceComponent tc = Tr.register(LTPAToken2Factory.class);
    private long expirationInMinutes;
    private byte[] primarySharedKey;
    private LTPAPublicKey primaryPublicKey;
    private LTPAPrivateKey primaryPrivateKey;
    private CopyOnWriteArrayList<LTPAValidationKeysInfo> validationKeys;
    private long expDiffAllowed;

    private LTPAKeyInfoManager keyInfoMgr;

    private String signingMode;
    private String classicalSigAlg;
    private String resolvedCipher;
    private int resolvedKeyLength;

    private PrivateKey primaryMLDSAPrivateKey;
    private PublicKey primaryMLDSAPublicKey;

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    public void initialize(@Sensitive Map tokenFactoryMap) {
        expirationInMinutes = (Long) tokenFactoryMap.get(LTPAConstants.EXPIRATION);
        primarySharedKey = (byte[]) tokenFactoryMap.get(LTPAConstants.PRIMARY_SECRET_KEY);
        primaryPublicKey = (LTPAPublicKey) tokenFactoryMap.get(LTPAConstants.PRIMARY_PUBLIC_KEY);
        primaryPrivateKey = (LTPAPrivateKey) tokenFactoryMap.get(LTPAConstants.PRIMARY_PRIVATE_KEY);
        expDiffAllowed = (Long) tokenFactoryMap.get(LTPAConfigurationImpl.KEY_EXP_DIFF_ALLOWED);
        validationKeys = (CopyOnWriteArrayList<LTPAValidationKeysInfo>) tokenFactoryMap.get(LTPAConstants.VALIDATION_KEYS);

        keyInfoMgr = (LTPAKeyInfoManager) tokenFactoryMap.get("keyInfoManager");

        signingMode = (String) tokenFactoryMap.get(LTPAConstants.CONFIGURED_SIGNING_MODE);
        classicalSigAlg = (String) tokenFactoryMap.get(LTPAConstants.CONFIGURED_CLASSICAL_SIG_ALG);
        resolvedCipher = (String) tokenFactoryMap.get(LTPAConstants.CONFIGURED_RESOLVED_CIPHER);
        resolvedKeyLength = (int) tokenFactoryMap.get(LTPAConstants.CONFIGURED_RESOLVED_KEY_LENGTH);

        byte[] mldsaPrivBytes = (byte[]) tokenFactoryMap.get(LTPAConstants.PRIMARY_MLDSA_PRIVATE_KEY);
        byte[] mldsaPubBytes = (byte[]) tokenFactoryMap.get(LTPAConstants.PRIMARY_MLDSA_PUBLIC_KEY);
        if (mldsaPrivBytes != null && mldsaPubBytes != null) {
            Object[] keys = buildMLDSAKeys(mldsaPrivBytes, mldsaPubBytes);
            if (keys != null) {
                primaryMLDSAPrivateKey = (PrivateKey) keys[0];
                primaryMLDSAPublicKey  = (PublicKey) keys[1];
            }
        }

        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Number of validationKeys: " + validationKeys.size());
        }
    }

    /**
     * Build ML-DSA key objects from raw encoded bytes.
     *
     * @param privateKeyBytes PKCS8-encoded private key bytes
     * @param publicKeyBytes  X509-encoded public key bytes
     * @return Array containing [PrivateKey, PublicKey] or null if construction fails
     */
    private Object[] buildMLDSAKeys(byte[] privateKeyBytes, byte[] publicKeyBytes) {
        long startBuild = System.currentTimeMillis();
        System.out.println("[LTPAToken2Factory] buildMLDSAKeys (ML-DSA): start;"
                + " privateKeyLen=" + (privateKeyBytes != null ? privateKeyBytes.length : 0)
                + ", publicKeyLen=" + (publicKeyBytes != null ? publicKeyBytes.length : 0) + " bytes");
        try {
            long startCrypto = System.currentTimeMillis();
            KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            PublicKey  publicKey  = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            long cryptoMs = System.currentTimeMillis() - startCrypto;

            long totalMs = System.currentTimeMillis() - startBuild;
            System.out.println("[LTPAToken2Factory] buildMLDSAKeys (ML-DSA): end;"
                    + " crypto (KeyFactory+generatePrivate+generatePublic)=" + cryptoMs + " ms, total=" + totalMs + " ms");
            return new Object[] { privateKey, publicKey };
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "buildMLDSAKeys: FAILED exception=" + e.getClass().getName() + ": " + e.getMessage(), e);
            }
            return null;
        }
    }

    /**
     * Load ML-DSA keys from a validation key file via the key info manager.
     * Used only for validation keys; primary ML-DSA keys are pre-built during initialize().
     *
     * @param keyFile The key file name
     * @return Array containing [PrivateKey, PublicKey] or null if not available
     */
    private Object[] loadMLDSAKeys(String keyFile) {
        byte[] privateKeyBytes = keyInfoMgr.getMLDSAPrivateKey(keyFile);
        byte[] publicKeyBytes  = keyInfoMgr.getMLDSAPublicKey(keyFile);
        if (privateKeyBytes == null || publicKeyBytes == null) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA keys not found in key file: " + keyFile);
            }
            return null;
        }
        return buildMLDSAKeys(privateKeyBytes, publicKeyBytes);
    }

    /** {@inheritDoc} */
    @Override
    public Token createToken(Map tokenData) throws TokenCreationFailedException {
        String userUniqueId = getUniqueId(tokenData);

        if ("pqc".equals(signingMode)) {
            if (primaryMLDSAPrivateKey != null && primaryMLDSAPublicKey != null) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "Creating token with signingMode=" + signingMode);
                }
                return new LTPAToken2(userUniqueId, expirationInMinutes,
                                      primarySharedKey, primaryPrivateKey, primaryPublicKey,
                                      primaryMLDSAPrivateKey, primaryMLDSAPublicKey, signingMode,
                                      null, resolvedCipher, resolvedKeyLength);
            } else {
                Tr.warning(tc, "ML-DSA keys not available for signingMode=" + signingMode + ", falling back to classical");
            }
        }

        // classical / none / fallback
        return new LTPAToken2(userUniqueId, expirationInMinutes,
                              primarySharedKey, primaryPrivateKey, primaryPublicKey,
                              null, null, signingMode, classicalSigAlg, resolvedCipher, resolvedKeyLength);
    }

    private String getUniqueId(Map tokenData) throws TokenCreationFailedException {
        String userUniqueId = (String) tokenData.get(LTPAConstants.UNIQUE_ID);
        if ((userUniqueId == null) || (userUniqueId.length() == 0)) {
            Tr.error(tc, "LTPA_TOKEN_SERVICE_INVALID_UNIQUE_ID");
            String formattedMessage = Tr.formatMessage(tc, "LTPA_TOKEN_SERVICE_INVALID_UNIQUE_ID");
            throw new TokenCreationFailedException(formattedMessage);
        }
        return userUniqueId;
    }

    /** {@inheritDoc} */
    @Override
    public Token validateTokenBytes(byte[] tokenBytes) throws InvalidTokenException, TokenExpiredException {
    // TODO: PQC #35556 - Task 2.7: Add PQC token validation
    // After loading RSA keys:
    // 1. Detect token version from token bytes (classical vs PQC vs hybrid)
    // 2. If PQC or hybrid, load ML-DSA public keys using loadMLDSAKeys()
    // 3. Pass to LTPAToken2 for verification
    // 4. LTPAToken2.isValid() will use PQCSignatureHelper for verification
    //
    // Note: Hybrid mode requires BOTH RSA and ML-DSA signatures to be valid
        return validateTokenBytes(tokenBytes, (String[]) null);
    }

    /** {@inheritDoc} */
    @FFDCIgnore(Exception.class)
    @Override
    public Token validateTokenBytes(byte[] tokenBytes, String... removeAttributes) throws InvalidTokenException, TokenExpiredException {
        Token validatedToken = null;

        if (primarySharedKey != null && (primaryMLDSAPublicKey != null || primaryPublicKey != null)) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "validateTokenBytes with primary keys");
            }

            try {
                if (primaryMLDSAPublicKey != null) {
                    validatedToken = new LTPAToken2(tokenBytes, primarySharedKey, primaryPrivateKey, primaryPublicKey,
                                                   primaryMLDSAPrivateKey, primaryMLDSAPublicKey, signingMode,
                                                   expDiffAllowed, removeAttributes);
                } else {
                    validatedToken = new LTPAToken2(tokenBytes, primarySharedKey, primaryPrivateKey, primaryPublicKey, expDiffAllowed, removeAttributes);
                }
                if (validatedToken != null) {
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "validateTokenBytes with primary keys (success)");
                    }
                    return validatedToken;
                }
            } catch (Exception e) {
                //If the token is expired then we do not want to continue processing validation keys below
                if (e instanceof com.ibm.websphere.security.auth.TokenExpiredException) {
                    if (tc.isEntryEnabled())
                        Tr.exit(tc, "validateTokenBytes (expired)");
                    throw (com.ibm.websphere.security.auth.TokenExpiredException) e;
                }
                //invalidToken exceptions should continue to check other keys below
            }
        }

        // validation keys (secondary keys)
        if (validationKeys != null && !validationKeys.isEmpty()) {
            Exception lastException = null;

            Iterator<LTPAValidationKeysInfo> validationKeysIterator = validationKeys.iterator();

            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "go through " + validationKeys.size() + " validationKeys");
            }
            while (validationKeysIterator.hasNext()) { // go through all validation keys until successfully validated the token
                LTPAValidationKeysInfo ltpaKeyInfo = validationKeysIterator.next();
                byte[] sharedKeyForValidation = ltpaKeyInfo.getSecretKey();

                LTPAPrivateKey ltpaPrivateKeyForValidation = ltpaKeyInfo.getLTPAPrivateKey();
                LTPAPublicKey ltpaPublicKeyForValidation = ltpaKeyInfo.getLTPAPublicKey();
                byte[] ltpaPqcPrivateKeyForValidation = ltpaKeyInfo.getMLDSAPrivateKey();
                byte[] ltpaPqcPublicKeyForValidation = ltpaKeyInfo.getMLDSAPublicKey();

                Object[] valMldsaKeys = loadMLDSAKeys(ltpaKeyInfo.getFilename());

                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "validationKey valMldsaKeys=" + (valMldsaKeys == null ? "null" : "present"));
                }

                if (ltpaKeyInfo.isValidUntilDateExpired()) {
                    validationKeys.remove(ltpaKeyInfo);
                } else {
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "validateTokenBytes with validationKeys: " + ltpaKeyInfo);
                    }

                    if (sharedKeyForValidation != null && (valMldsaKeys != null || ltpaPublicKeyForValidation != null)) {
                        try {
                                if (valMldsaKeys != null) {
                                    // signingMode is not passed — LTPAToken2.verify() routes on sigAlgForVerify
                                    // which is set from the token's own content, so it is correct regardless of
                                    // which keys happen to be present in this validation entry.
                                    validatedToken = new LTPAToken2(tokenBytes, sharedKeyForValidation, ltpaPrivateKeyForValidation, ltpaPublicKeyForValidation,
                                                                   (PrivateKey) valMldsaKeys[0], (PublicKey) valMldsaKeys[1], signingMode,
                                                                   expDiffAllowed, removeAttributes);
                                } else {
                                    validatedToken = new LTPAToken2(tokenBytes, sharedKeyForValidation, ltpaPrivateKeyForValidation, ltpaPublicKeyForValidation, expDiffAllowed, removeAttributes);
                                }
                            if (validatedToken != null) {
                                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                                    Tr.debug(tc, "validateTokenBytes with validationKeys (success)");
                                }
                                return validatedToken;
                            }
                        } catch (Exception e) {
                            if (e instanceof com.ibm.websphere.security.auth.TokenExpiredException) {
                                if (tc.isEntryEnabled())
                                    Tr.exit(tc, "validateTokenBytes (expired)");
                                throw (com.ibm.websphere.security.auth.TokenExpiredException) e;
                            }

                            lastException = e;
                            // no ffdc needed.
                            Tr.debug(tc, "Exception validating LTPAToken using validation keys.", new Object[] { e.getMessage() });
                        }
                    }
                }
            }

            if (lastException != null && lastException instanceof com.ibm.websphere.security.auth.InvalidTokenException) {
                if (tc.isEntryEnabled())
                    Tr.exit(tc, "validateTokenBytes (invalid token)");
                throw (com.ibm.websphere.security.auth.InvalidTokenException) lastException;
            } else if (lastException != null) {
                if (tc.isEntryEnabled())
                    Tr.exit(tc, "validateTokenBytes (" + lastException.getClass().getName() + ")");
                throw new com.ibm.websphere.security.auth.InvalidTokenException(lastException.getMessage(), lastException);
            } else {
                if (tc.isEntryEnabled())
                    Tr.exit(tc, "validateTokenBytes (unknown error)");
                throw new com.ibm.websphere.security.auth.InvalidTokenException("Error validating LTPA token.");
            }
        }

        if (tc.isEntryEnabled())
            Tr.exit(tc, "validateTokenBytes (no keys)");
        throw new com.ibm.websphere.security.auth.InvalidTokenException("Token factory not properly initialized.");
    }

}
