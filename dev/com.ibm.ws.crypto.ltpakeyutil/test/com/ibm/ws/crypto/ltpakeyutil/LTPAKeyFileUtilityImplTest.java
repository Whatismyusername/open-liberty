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

import java.util.Properties;

import org.junit.Assert;
import org.junit.Test;

/**
 *
 */
public class LTPAKeyFileUtilityImplTest {

    @Test
    public void testLTPAKeyGeneration() throws Exception {
    	LTPAKeyFileUtilityImpl creator = new LTPAKeyFileUtilityImpl();
        Properties keyInfo = creator.generateLTPAKeys("WebAS".getBytes(), "myRealm");

        // Check the secret key.
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_SECRETKEY));

        // Check the private key.
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_PRIVATEKEY));

        // Check the public key.
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_PUBLICKEY));

        // Check the realm.
        Assert.assertEquals("myRealm", keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_REALM));

        // Check the host.
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.CREATION_HOST_PROPERTY));

        // Check the version.
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.LTPA_VERSION_PROPERTY));

        // Check the creation date.
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.CREATION_DATE_PROPERTY));
    }

    @Test
    public void testLTPAKeyGenerationV4Symmetric() throws Exception {
        LTPAKeyFileUtilityImpl creator = new LTPAKeyFileUtilityImpl();
        Properties keyInfo = creator.generateLTPAKeys("WebAS".getBytes(), null, null, null, "symmetricRealm", "symmetric", null, 0);

        // Check the version is 4.0
        Assert.assertEquals("4.0", keyInfo.get(LTPAKeyFileUtility.LTPA_VERSION_PROPERTY));

        // Check the secret key is present
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_SECRETKEY_V1));

        // Check no RSA or ML-DSA keys are present
        Assert.assertNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_PRIVATEKEY));
        Assert.assertNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_PUBLICKEY));
        Assert.assertNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_MLDSA_PRIVATEKEY));
        Assert.assertNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_MLDSA_PUBLICKEY));

        // Check realm and creation properties
        Assert.assertEquals("symmetricRealm", keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_REALM));
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.CREATION_HOST_PROPERTY));
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.CREATION_DATE_PROPERTY));
    }

    @Test
    public void testClassicalModeIgnoresStrayMldsaAlgorithm() throws Exception {
        LTPAKeyFileUtilityImpl creator = new LTPAKeyFileUtilityImpl();
        Properties keyInfo = creator.generateLTPAKeys("WebAS".getBytes(), null, null, null, "realm", "classical", "ML-DSA-65", 128);

        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_PRIVATEKEY));
        Assert.assertNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_MLDSA_PRIVATEKEY));
    }

    @Test
    public void testSymmetricModeIgnoresStrayArguments() throws Exception {
        LTPAKeyFileUtilityImpl creator = new LTPAKeyFileUtilityImpl();
        Properties keyInfo = creator.generateLTPAKeys("WebAS".getBytes(), null, null, null, "realm", "SYMMETRIC", "ML-DSA-65", 256);

        Assert.assertEquals("4.0", keyInfo.get(LTPAKeyFileUtility.LTPA_VERSION_PROPERTY));
        Assert.assertNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_PRIVATEKEY));
        Assert.assertNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_MLDSA_PRIVATEKEY));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPqcModeRequiresMldsaAlgorithm() throws Exception {
        new LTPAKeyFileUtilityImpl().generateLTPAKeys("WebAS".getBytes(), null, null, null, "realm", "pqc", null, 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridModeRequiresMldsaAlgorithm() throws Exception {
        new LTPAKeyFileUtilityImpl().generateLTPAKeys("WebAS".getBytes(), null, null, null, "realm", "hybrid", null, 256);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridModeRequiresClassicalKeySize() throws Exception {
        new LTPAKeyFileUtilityImpl().generateLTPAKeys("WebAS".getBytes(), null, null, null, "realm", "hybrid", "ML-DSA-65", 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUnknownSigningModeRejected() throws Exception {
        new LTPAKeyFileUtilityImpl().generateLTPAKeys("WebAS".getBytes(), null, null, null, "realm", "bogus", null, 0);
    }

}
