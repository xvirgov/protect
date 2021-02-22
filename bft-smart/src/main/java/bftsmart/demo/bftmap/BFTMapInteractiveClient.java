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
package bftsmart.demo.bftmap;

import java.io.Console;
import java.io.IOException;
import java.util.Scanner;
import java.util.TreeMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author sweta
 */
public class BFTMapInteractiveClient {

	private static final Logger logger = LogManager.getLogger(BFTMapInteractiveClient.class);

	public static void main(String[] args) throws IOException {
		if (args.length < 1) {
			logger.debug("Usage: java BFTMapInteractiveClient <process id>");
			System.exit(-1);
		}

		BFTMap bftMap = new BFTMap(Integer.parseInt(args[0]));

		Console console = System.console();
		Scanner sc = new Scanner(System.in);

		while (true) {

			logger.debug("select a command : 1. CREATE A NEW TABLE OF TABLES");
			logger.debug("select a command : 2. REMOVE AN EXISTING TABLE");
			logger.debug("select a command : 3. GET THE SIZE OF THE TABLE OF TABLES");
			logger.debug("select a command : 4. PUT VALUES INTO A TABLE");
			logger.debug("select a command : 5. GET VALUES FROM A TABLE");
			logger.debug("select a command : 6. GET THE SIZE OF A TABLE");
			logger.debug("select a command : 7. REMOVE AN EXISTING TABLE");
			logger.debug("select a command : 11. EXIT");

			int cmd = sc.nextInt();

			switch (cmd) {
			// operations on the table
			case BFTMapRequestType.TAB_CREATE:
				String tableName;
				boolean tableExists = false;
				do {
					tableName = console.readLine("Enter the HashMap name: ");
					tableExists = bftMap.containsKey(tableName);
					if (!tableExists) {
						// if the table name does not exist then create the table
						bftMap.put(tableName, new TreeMap<String, byte[]>());
					}
				} while (tableExists);
				break;

			case BFTMapRequestType.SIZE_TABLE:
				// obtain the size of the table of tables.
				logger.debug("Computing the size of the table");
				int size = bftMap.size();
				logger.debug("The size of the table of tables is: " + size);
				break;

			case BFTMapRequestType.TAB_REMOVE:
				// Remove the table entry
				tableExists = false;
				tableName = null;
				logger.debug("Removing table");
				tableName = console.readLine("Enter the valid table name you want to remove: ");
				tableExists = bftMap.containsKey(tableName);
				if (tableExists) {
					bftMap.remove(tableName);
					logger.debug("Table removed");
				} else
					logger.debug("Table not found");
				break;

			// operations on the hashmap
			case BFTMapRequestType.PUT:
				logger.debug("Execute put function");
				tableExists = false;
				tableName = null;
				size = -1;
				tableName = console.readLine("Enter the valid table name in which you want to insert data: ");
				String key = console.readLine("Enter a numeric key for the new record in the range 0 to 9999: ");
				String value = console.readLine("Enter the value for the new record: ");

				byte[] resultBytes;
				tableExists = bftMap.containsKey(tableName);
				if (tableExists) {
					while (key.length() < 4)
						key = "0" + key;
					byte[] byteArray = value.getBytes();
					resultBytes = bftMap.putEntry(tableName, key, byteArray);
				} else
					logger.debug("Table not found");
				break;

			case BFTMapRequestType.GET:
				logger.debug("Execute get function");
				tableExists = false;
				boolean keyExists = false;
				tableName = null;
				key = null;
				tableName = console.readLine("Enter the valid table name from which you want to get the values: ");
				tableExists = bftMap.containsKey(tableName);
				if (tableExists) {
					key = console.readLine("Enter the key: ");
					while (key.length() < 4)
						key = "0" + key;
					keyExists = bftMap.containsKey1(tableName, key);
					if (keyExists) {
						resultBytes = bftMap.getEntry(tableName, key);
						logger.debug("The value received from GET is: " + new String(resultBytes));
					} else
						logger.debug("Key not found");
				} else
					logger.debug("Table not found");
				break;

			case BFTMapRequestType.SIZE:
				logger.debug("Execute get function");
				tableExists = false;
				tableName = null;
				size = -1;
				tableName = console.readLine("Enter the valid table whose size you want to detemine: ");

				tableExists = bftMap.containsKey(tableName);
				if (tableExists) {
					size = bftMap.size1(tableName);
					logger.debug("The size is: " + size);
				} else {
					logger.debug("Table not found");
				}
				break;
			case BFTMapRequestType.REMOVE:
				logger.debug("Execute get function");
				tableExists = false;
				keyExists = false;
				tableName = null;
				key = null;
				tableName = console.readLine("Enter the table name from which you want to remove: ");
				tableExists = bftMap.containsKey(tableName);
				if (tableExists) {
					key = console.readLine("Enter the valid key: ");
					keyExists = bftMap.containsKey1(tableName, key);
					if (keyExists) {
						byte[] result2 = bftMap.removeEntry(tableName, key);
						logger.debug("The previous value was : " + new String(result2));
					} else
						logger.debug("Key not found");
				} else
					logger.debug("Table not found");
				break;
			case BFTMapRequestType.EXIT:
				System.exit(-1);
			}
		}
	}
}
