/*******************************************************************************
 * Copyright (c) 2012, 2026 IBM Corporation and others.
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
package com.ibm.ws.security.token.ltpa;

import java.util.List;
import java.util.Properties;

import com.ibm.wsspi.security.ltpa.TokenFactory;

/**
 * Service class to indicate the LTPA configuration is available and
 * ready for use.
 */
public interface LTPAConfiguration {

    /**
     * The token keys file.
     */
    public static final String CFG_KEY_IMPORT_FILE = "keysFileName";

    /**
     * The token keys file password.
     */
    public static final String CFG_KEY_PASSWORD = "keysPassword"; // pragma: allowlist secret

    /**
     * The token expiration.
     */
    public static final String CFG_KEY_TOKEN_EXPIRATION = "expiration";

    /**
     * The token keys file's monitor interval.
     */
    public static final String CFG_KEY_MONITOR_INTERVAL = "monitorInterval";

    /**
     * The Boolean to monitor the token keys file's directory.
     */
    public static final String CFG_KEY_MONITOR_VALIDATION_KEYS_DIR = "monitorValidationKeysDir";

    /**
     * The token keys file's update method or trigger.
     */
    public static final String CFG_KEY_UPDATE_TRIGGER = "updateTrigger";

    /**
     * The LTPA token version.
     * Valid values: "2" (LTPA Token Version 2 - RSA only), "3" (LTPA Token Version 3 - Hybrid PQC)
     */
    public static final String CFG_KEY_TOKEN_VERSION = "tokenVersion";

    /**
     * The token validation keys.
     */
    static final String CFG_KEY_VALIDATION_KEYS = "validationKeys";

    /**
     * The token validation keys file(s).
     */
    static final String CFG_KEY_VALIDATION_FILE_NAME = "fileName";

    /**
     * The token validation keys file password.
     */
    static final String CFG_KEY_VALIDATION_PASSWORD = "password";

    /**
     * The the date-time to stop using the token validation keys.
     */
    static final String CFG_KEY_VALIDATION_VALID_UNTIL_DATE = "validUntilDate";

    // ========== PQC Configuration Properties (Issue #35556) ==========
    
    /**
     * The signing mode for LTPA tokens.
     * Valid values: "classical", "pqc", "none"
     */
    public static final String CFG_KEY_SIGNING_MODE = "signingMode";

    /**
     * The classical digital signature algorithm.
     * Valid values: "SHA1withRSA" (non-FIPS default), "SHA512withRSA" (FIPS default)
     */
    public static final String CFG_KEY_CLASSICAL_SIGNATURE_ALGORITHM = "classicalSignatureAlgorithm";

    /**
     * The RSA key size in bits for the classical signature algorithm.
     * Valid values: "1024" (non-FIPS default), "2048" (FIPS default), "4096"
     */
    public static final String CFG_KEY_CLASSICAL_KEY_SIZE = "classicalKeySize";

    /**
     * The ML-DSA algorithm variant for quantum-resistant signatures.
     * Valid values: "ML-DSA-44", "ML-DSA-65" (PQC default), "ML-DSA-87"
     */
    public static final String CFG_KEY_PQC_SIGNATURE_ALGORITHM = "pqcSignatureAlgorithm";

    /**
     * The symmetric encryption algorithm for LTPA token payloads.
     * Valid values: "AES-CBC-128" (non-FIPS default), "AES-CBC-256" (FIPS default), "AES-GCM-256", "none"
     */
    public static final String CFG_KEY_ENCRYPTION_ALGORITHM = "encryptionAlgorithm";

    /**
     * The policy for verifying signatures on reception of a hybrid LTPA token.
     * Valid values: "both" (default), "pqc", "classical"
     */
    public static final String CFG_KEY_HYBRID_VERIFICATION_POLICY = "hybridVerificationPolicy";

    /**
     * Internal property used to distinguish configured validation keys from non-configured validation keys.
     * Configured validation keys are explicitly defined in the server.xml using <validationKeys /> and require a password.
     * Non-configured validation keys are picked up when <ltpa monitorValidationKeysDir="true" /> is set and uses the same password as the primary ltpa key.
     *
     * Currently only used to determine if we should re-encrypt the validation key when the primary ltpa key is re-encrypted and it is a non-configured validation key.
     */
    static final String INTERNAL_KEY_IS_CONFIGURED_VALIDATION_KEY = "isConfiguredValidationKey";

    /**
     * @return TokenFactory instance corresponding to this LTPA configuration
     */
    TokenFactory getTokenFactory();

    /**
     * @return LTPAKeyInfoManager instance corresponding to this LTPA configuration
     */
    LTPAKeyInfoManager getLTPAKeyInfoManager();

    /**
     * @return LTPA key file
     */
    String getPrimaryKeyFile();

    /**
     * @return LTPA key password
     */
    String getPrimaryKeyPassword();

    /**
     * @return boolean for try to re-encrypt ltpa keys
     */
    boolean getTryToReEncryptLtpaKeys();

    /**
     * @return LTPA expiration
     */
    long getTokenExpiration();

    /**
     * Get the LTPA token version.
     *
     * @return The token version: "2" (LTPA Token Version 2 - RSA only) or "3" (LTPA Token Version 3 - Hybrid PQC)
     */
    String getTokenVersion();

    /**
     * @return authFiler reference
     */
    String getAuthFilterRef();

    /**
     * @return Maximum expiration difference allowed
     */
    long getExpirationDifferenceAllowed();

    
    // ========== Signing Configuration Getters ==========

    /**
     * Get the signing mode for LTPA tokens.
     *
     * @return The signing mode: "classical", "pqc", "hybrid", or "none"
     */
    String getSigningMode();

    /**
     * Get the classical digital signature algorithm.
     *
     * @return The classical signature algorithm: "SHA1WithRSA" or "SHA512WithRSA"
     */
    String getClassicalSignatureAlgorithm();

    /**
     * Get the RSA key size in bits for the classical signature algorithm.
     *
     * @return The key size in bits: 1024, 2048, or 4096
     */
    int getClassicalKeySize();

    /**
     * Get the ML-DSA algorithm variant for quantum-resistant signatures.
     *
     * @return The PQC signature algorithm: "ML-DSA-44", "ML-DSA-65", or "ML-DSA-87"
     */
    String getPqcSignatureAlgorithm();

    /**
     * Get the symmetric encryption algorithm for LTPA token payloads.
     *
     * @return The encryption algorithm: "AES-CBC-128", "AES-CBC-256", "AES-GCM-256", or "none"
     */
    String getEncryptionAlgorithm();

    /**
     * Get the hybrid verification policy for LTPA tokens.
     *
     * @return The verification policy: "both", "pqc", or "classical"
     */
    String getHybridVerificationPolicy();

    /**
     * Get the resolved JCE cipher string for use in encrypt/decrypt operations.
     *
     * @return e.g. "AES/CBC/PKCS5Padding", "AES/GCM/NoPadding", or null for "none"
     */
    String getResolvedCipher();

    /**
     * Get the resolved AES key length in bytes for use in encrypt/decrypt operations.
     *
     * @return e.g. 16 (AES-128) or 32 (AES-256), or 0 for "none"
     */
    int getResolvedKeyLength();

    /**
     * @return monitor interval
     */
    long getMonitorInterval();

    /**
     * @return boolean for monitoring validation keys dir
     */
    boolean getMonitorValidationKeysDir();

    /**
     * @return update trigger
     */
    String getUpdateTrigger();

    /**
     * @return validation Keys
     */
    List<Properties> getValidationKeys();
    
}
