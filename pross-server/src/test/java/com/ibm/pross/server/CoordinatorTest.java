/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server;

public class CoordinatorTest {
/**
	public static Administration DEFAULT_ADMINISTRATION;

 	private static final Logger logger = LogManager.getLogger(CoordinatorTest.class);

 @BeforeClass
	public static void setupBeforeClass() throws NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException
	{
		Security.addProvider(new BouncyCastleProvider());
		CommonConfiguration.CURVE.getPointHasher().hashToCurve(new byte[1]);
		DEFAULT_ADMINISTRATION = createDefaultAdministration();
	}
	
	private static Administration createDefaultAdministration() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException
	{
		// Create threshold parameters
		final int n = 5;
		final int updateThreshold = 4;
		final int threshold = 3;

		final Administration administration = new Administration(n, threshold, updateThreshold, false);
		
		return administration;
	}
	
	
	@Test
	public void testVerifyAllShares() {
		fail("Not yet implemented");
	}

	@Test
	public void testVerify() {
		fail("Not yet implemented");
	}

	@Test
	public void testRebuildAll() {
		fail("Not yet implemented");
	}

	@Test
	public void testRebuild() {
		fail("Not yet implemented");
	}

	@Test
	public void testUpdateAllKeyPairs() {
		fail("Not yet implemented");
	}

	@Test
	public void testUpdateKeyPair() {
		fail("Not yet implemented");
	}

	@Test
	public void testProcessUpdatePhase() {
		fail("Not yet implemented");
	}


	
	@Test
	public void testPrfClient() throws Exception {

		// Create shareholders and client
		final PrfClient prfClient = DEFAULT_ADMINISTRATION.provisionClient();

		// Derive a key
		logger.info("Deriving KDF from bytes");
		final byte[] input = "test".getBytes(StandardCharsets.UTF_8);
		final HmacKeyDerivationFunction hkdf = prfClient.deriveKeyGeneratorFromBytes(input);
		Assert.assertNotNull(hkdf);
		
		// Wrap a key
		logger.info("Wrapping a key");
		final EcPoint output1 = prfClient.derivePointFromBytes(input);
		logger.info("Prf Output 1: " + output1);
		
		// Unwrap a key
		final EcPoint output2 = prfClient.derivePointFromBytes(input);
		logger.info("Prf Output 2: " + output2);
		Assert.assertEquals(output1, output2);
	}
*/
}
