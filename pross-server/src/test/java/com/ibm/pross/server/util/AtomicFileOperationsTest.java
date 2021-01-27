package com.ibm.pross.server.util;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;



public class AtomicFileOperationsTest {

	private static final Logger logger = LogManager.getLogger(AtomicFileOperationsTest.class);

	@Test
	public void testAtomicWrite() throws IOException {
		
		final File tempFile = File.createTempFile("test-file", UUID.randomUUID().toString());
		tempFile.deleteOnExit();

		for (int i = 0; i < 10; i++) {
			final String str = new String("hello-" + i);
			
			long start = System.nanoTime();
			AtomicFileOperations.atomicWriteString(tempFile, str);
			long end = System.nanoTime();
			logger.info("Atomically wrote file in: " + (end - start) + " ns");
			logger.info("Wrote to: " + tempFile.getAbsolutePath());
			
			//String readString = (String) AtomicFileOperations.readObject(tempFile);
			//Assert.assertEquals(str, readString);
		}
		
		tempFile.delete();
	}

}
