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
package com.ibm.ws.security.token.ltpa;

import java.util.List;
import java.util.Properties;

import test.UTLocationHelper;

/**
 * Test helper for loading or creating LTPA key files with the default
 * classical (RSA-1024) signing configuration.
 */
public class LTPAKeyInfoManagerTestUtil {

    private LTPAKeyInfoManagerTestUtil() {}

    public static void prepareClassical(LTPAKeyInfoManager keyInfoManager, String keyFile, byte[] keyPassword,
                                        List<Properties> validationKeys, boolean tryToReEncryptLtpaKeys) throws Exception {
        keyInfoManager.prepareLTPAKeyInfo(UTLocationHelper.getLocationManager(), keyFile, keyPassword,
                                          validationKeys, tryToReEncryptLtpaKeys, "classical", null, 1024 / 8);
    }
}
