/**
Copyright (c) 2007-2013 Alysson Bessani, Eduardo Alchieri, Paulo Sousa, and the authors indicated in the @author tags

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package bftsmart.demo.logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import bftsmart.tom.ServiceProxy;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Example client that updates a BFT replicated service (a log).
 * 
 * @author alysson
 */
public class LoggerClient {

	private static final Logger logger = LogManager.getLogger(LoggerClient.class);

	public static String generateString(int length)
	{
		final Random rand = new Random();
		final StringBuffer buffer = new StringBuffer();
		
		for (int i = 0; i < length; i++)
		{
			final int r = rand.nextInt(26) + 65;
			buffer.append(Character.toString ((char) r));
		}
		return buffer.toString();
	}

	public static void main(String[] args) throws IOException {
		if (args.length < 2) {
			logger.info("Usage: java ... CounterClient <process id> <increment> [<number of operations>]");
			logger.info("       if <increment> equals 0 the request will be read-only");
			logger.info("       default <number of operations> equals 1000");
			System.exit(-1);
		}

		ServiceProxy counterProxy = new ServiceProxy(Integer.parseInt(args[0]));

//		Logger.debug = false;

		try {

			int strLen = Integer.parseInt(args[1]);
			int numberOfOps = (args.length > 2) ? Integer.parseInt(args[2]) : 1000;

			for (int i = 0; i < numberOfOps; i++) {

				String msg = generateString(strLen);
				
				System.out.print("Invocation " + i + ", message = " + msg);
				byte[] reply = counterProxy.invokeOrdered(msg.getBytes(StandardCharsets.UTF_8)); // magic happens here

				if (reply != null) {
					String newValue = new String(reply, StandardCharsets.UTF_8);
					logger.info(", returned value: " + newValue);
				} else {
					logger.info(", ERROR! Exiting.");
					break;
				}
			}
		} catch (NumberFormatException e) {
			counterProxy.close();
		}
	}
}
