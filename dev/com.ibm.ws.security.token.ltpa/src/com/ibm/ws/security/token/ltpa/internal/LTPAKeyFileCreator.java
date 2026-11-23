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
package com.ibm.ws.security.token.ltpa.internal;

import java.util.Properties;

import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.ws.crypto.ltpakeyutil.LTPAKeyFileUtility;
import com.ibm.wsspi.kernel.service.location.WsLocationAdmin;

/**
 * Utility class to create the LTPA keys file.
 */
public interface LTPAKeyFileCreator extends LTPAKeyFileUtility {

    /**
     * Create the LTPA keys file at the specified location with newly generated keys.
     * <p>
     * Access the keyFile using the WsLocationAdmin
     *
     * @param locService
     * @param keyFile
     * @param keyPasswordBytes
     * @param signingMode      signing mode ("classical", "pqc", "hybrid", "symmetric", "none")
     * @param mldsaAlgorithm   ML-DSA algorithm for PQC/hybrid mode, or null
     * @param classicalKeySize RSA key size in bytes (128=RSA-1024, 256=RSA-2048); 0 uses default
     * @return A Properties object containing the various attributes created for the LTPA keys
     * @throws Exception
     */
    public Properties createLTPAKeysFile(WsLocationAdmin locService, String keyFile, @Sensitive byte[] keyPasswordBytes,
                                         String signingMode, String mldsaAlgorithm, int classicalKeySize) throws Exception;

    /**
     * Create the LTPA keys file at the specified location by re-encrypting existing
     * classical (shared key + RSA) keys with the specified password bytes.
     * <p>
     * Access the keyFile using the WsLocationAdmin
     *
     * @param locService
     * @param keyFile
     * @param keyPasswordBytes
     * @param sharedKeyBytes
     * @param privateKeyBytes
     * @param publicKeyBytes
     * @return A Properties object containing the various attributes created for the LTPA keys
     * @throws Exception
     */
    public Properties createLTPAKeysFile(WsLocationAdmin locService, String keyFile, @Sensitive byte[] keyPasswordBytes,
                                         @Sensitive byte[] sharedKeyBytes, @Sensitive byte[] privateKeyBytes, @Sensitive byte[] publicKeyBytes) throws Exception;

}