/*******************************************************************************
 * Copyright (c) 2011, 2026 IBM Corporation and others.
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

public class LTPAConstants {

    /**
     * Used to identify the expiration limit of the LTPA2 token.
     */
    protected static final String EXPIRATION = "expiration";

    /**
     * Used to identify the primary LTPA shared key.
     */
    protected static final String PRIMARY_SECRET_KEY = "primary_ltpa_shared_key";

    /**
     * Used to identify the primary LTPA private key.
     */
    protected static final String PRIMARY_PRIVATE_KEY = "primary_ltpa_private_key";

    /**
     * Used to identify the primary LTPA public key.
     */
    protected static final String PRIMARY_PUBLIC_KEY = "primary_ltpa_public_key";

    /**
     * Used to identify the validation LTPA keys
     */
    public static final String VALIDATION_KEYS = "ltpa_validation_keys";

    /**
     * Used to identify the primary PQC keys (RSA + ML-KEM) for LTPA3 tokens.
     * @deprecated Use {@link #PRIMARY_HYBRID_KEYS} instead
     */
    @Deprecated
    protected static final String PRIMARY_PQC_KEYS = "primary_pqc_keys";

    /**
     * Used to identify the primary hybrid keys (RSA + ML-DSA + ML-KEM) for LTPA3 tokens.
     */
    protected static final String PRIMARY_HYBRID_KEYS = "primary_hybrid_keys";

    /**
     * Used to identify the primary ML-DSA private key (PQC mode).
     */
    protected static final String PRIMARY_MLDSA_PRIVATE_KEY = "primary_mldsa_private_key";

    /**
     * Used to identify the primary ML-DSA public key (PQC mode).
     */
    protected static final String PRIMARY_MLDSA_PUBLIC_KEY = "primary_mldsa_public_key";

    /**
     * Used to identify the unique identifier of a user.
     */
    protected static final String UNIQUE_ID = "unique_id";

    // ========== Configured Hybrid Signing Keys ==========

    /** Effective signing mode after applying defaults and cross-validation rules. */
    protected static final String CONFIGURED_SIGNING_MODE = "configured_signing_mode";

    /** Effective classical signature algorithm (e.g. SHA1withRSA, SHA512withRSA). */
    protected static final String CONFIGURED_CLASSICAL_SIG_ALG = "configured_classical_sig_alg";

    /** JCA cipher string resolved from encryptionAlgorithm (e.g. AES/CBC/PKCS5Padding, AES/GCM/NoPadding). */
    protected static final String CONFIGURED_RESOLVED_CIPHER = "configured_resolved_cipher";

    /** AES key length in bytes resolved from encryptionAlgorithm (e.g. 16 for AES-128, 32 for AES-256). */
    protected static final String CONFIGURED_RESOLVED_KEY_LENGTH = "configured_resolved_key_length";

    /** Effective hybrid verification policy (both, pqc, classical). */
    protected static final String CONFIGURED_HYBRID_VERIFY_POLICY = "configured_hybrid_verify_policy";
}
