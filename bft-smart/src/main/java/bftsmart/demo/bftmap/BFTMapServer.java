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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.Map;

import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author sweta
 * 
 *         This class will create a ServiceReplica and will initialize it with a
 *         implementation of Executable and Recoverable interfaces.
 */
public class BFTMapServer extends DefaultSingleRecoverable {

	private static final Logger logger = LogManager.getLogger(BFTMapServer.class);

	MapOfMaps tableMap = null;
	ServiceReplica replica = null;

	// The constructor passes the id of the server to the super class
	public BFTMapServer(int id) {

		tableMap = new MapOfMaps();
		replica = new ServiceReplica(id, this, this);
	}

	public static void main(String[] args) {
		if (args.length < 1) {
			logger.debug("Use: java BFTMapServer <processId>");
			System.exit(-1);
		}
		new BFTMapServer(Integer.parseInt(args[0]));
	}

	@Override
	public byte[] appExecuteOrdered(byte[] command, MessageContext msgCtx) {
		try {
			ByteArrayInputStream in = new ByteArrayInputStream(command);
			ByteArrayOutputStream out = null;
			byte[] reply = null;
			int cmd = new DataInputStream(in).readInt();
			switch (cmd) {
			// operations on the hashmap
			case BFTMapRequestType.PUT:
				String tableName = new DataInputStream(in).readUTF();
				String key = new DataInputStream(in).readUTF();
				String value = new DataInputStream(in).readUTF();
				byte[] valueBytes = value.getBytes();
				logger.debug("Key received: " + key);
				byte[] ret = tableMap.addData(tableName, key, valueBytes);
				if (ret == null) {
					// logger.debug("Return is null, so there was no data before");
					ret = new byte[0];
				}
				reply = valueBytes;
				break;
			case BFTMapRequestType.REMOVE:
				tableName = new DataInputStream(in).readUTF();
				key = new DataInputStream(in).readUTF();
				// logger.debug("Key received: " + key);
				valueBytes = tableMap.removeEntry(tableName, key);
				value = new String(valueBytes);
				logger.debug("Value removed is : " + value);
				out = new ByteArrayOutputStream();
				new DataOutputStream(out).writeBytes(value);
				reply = out.toByteArray();
				out.close();
				break;
			case BFTMapRequestType.TAB_CREATE:
				tableName = new DataInputStream(in).readUTF();
				// ByteArrayInputStream in1 = new ByteArrayInputStream(command);
				ObjectInputStream objIn = new ObjectInputStream(in);
				Map<String, byte[]> table = null;
				try {
					table = (Map<String, byte[]>) objIn.readObject();
				} catch (ClassNotFoundException ex) {
					logger.error(ex);
				}
				Map<String, byte[]> tableCreated = tableMap.addTable(tableName, table);
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				ObjectOutputStream objOut = new ObjectOutputStream(bos);
				objOut.writeObject(tableCreated);
				objOut.close();
				in.close();
				reply = bos.toByteArray();
				break;
			case BFTMapRequestType.TAB_REMOVE:
				tableName = new DataInputStream(in).readUTF();
				table = tableMap.removeTable(tableName);
				bos = new ByteArrayOutputStream();
				objOut = new ObjectOutputStream(bos);
				objOut.writeObject(table);
				objOut.close();
				objOut.close();
				reply = bos.toByteArray();
				break;

			case BFTMapRequestType.SIZE_TABLE:
				int size1 = tableMap.getNumOfTables();
				// logger.debug("Size " + size1);
				out = new ByteArrayOutputStream();
				new DataOutputStream(out).writeInt(size1);
				reply = out.toByteArray();
				out.close();
				break;
			case BFTMapRequestType.GET:
				tableName = new DataInputStream(in).readUTF();
				logger.debug("tablename: " + tableName);
				key = new DataInputStream(in).readUTF();
				// logger.debug("Key received: " + key);
				valueBytes = tableMap.getEntry(tableName, key);
				value = new String(valueBytes);
				logger.debug("The value to be get is: " + value);
				out = new ByteArrayOutputStream();
				new DataOutputStream(out).writeBytes(value);
				reply = out.toByteArray();
				out.close();
				break;
			case BFTMapRequestType.SIZE:
				String tableName2 = new DataInputStream(in).readUTF();
				int size = tableMap.getSize(tableName2);
				out = new ByteArrayOutputStream();
				new DataOutputStream(out).writeInt(size);
				reply = out.toByteArray();
				out.close();
				break;
			case BFTMapRequestType.CHECK:
				tableName = new DataInputStream(in).readUTF();
				key = new DataInputStream(in).readUTF();
				// logger.debug("Table Key received: " + key);
				valueBytes = tableMap.getEntry(tableName, key);
				boolean entryExists = valueBytes != null;
				out = new ByteArrayOutputStream();
				new DataOutputStream(out).writeBoolean(entryExists);
				reply = out.toByteArray();
				out.close();
				break;
			case BFTMapRequestType.TAB_CREATE_CHECK:
				tableName = new DataInputStream(in).readUTF();
				// logger.debug("Table of Table Key received: " + tableName);
				table = tableMap.getTable(tableName);
				boolean tableExists = (table != null);
				logger.debug("Table exists: " + tableExists);
				out = new ByteArrayOutputStream();
				new DataOutputStream(out).writeBoolean(tableExists);
				reply = out.toByteArray();
				out.close();
				break;
			}
			in.close();
			return reply;
		} catch (IOException ex) {
			ex.printStackTrace();
			return null;
		}
	}

	@Override
	public byte[] appExecuteUnordered(byte[] command, MessageContext msgCtx) {
		try {
			ByteArrayInputStream in = new ByteArrayInputStream(command);
			ByteArrayOutputStream out = null;
			byte[] reply = null;
			int cmd = new DataInputStream(in).readInt();
			switch (cmd) {
			case BFTMapRequestType.SIZE_TABLE:
				int size1 = tableMap.getNumOfTables();
				// logger.debug("Size " + size1);
				out = new ByteArrayOutputStream();
				new DataOutputStream(out).writeInt(size1);
				reply = out.toByteArray();
				out.close();
				break;
			case BFTMapRequestType.GET:
				String tableName = new DataInputStream(in).readUTF();
				logger.debug("tablename: " + tableName);
				String key = new DataInputStream(in).readUTF();
				// logger.debug("Key received: " + key);
				byte[] valueBytes = tableMap.getEntry(tableName, key);
				String value = new String(valueBytes);
				logger.debug("The value to be get is: " + value);
				out = new ByteArrayOutputStream();
				new DataOutputStream(out).writeBytes(value);
				reply = out.toByteArray();
				out.close();
				break;
			case BFTMapRequestType.SIZE:
				String tableName2 = new DataInputStream(in).readUTF();
				int size = tableMap.getSize(tableName2);
				// logger.debug("Size " + size);
				out = new ByteArrayOutputStream();
				new DataOutputStream(out).writeInt(size);
				reply = out.toByteArray();
				out.close();
				break;
			case BFTMapRequestType.CHECK:
				tableName = new DataInputStream(in).readUTF();
				key = new DataInputStream(in).readUTF();
				// logger.debug("Table Key received: " + key);
				valueBytes = tableMap.getEntry(tableName, key);
				boolean entryExists = valueBytes != null;
				out = new ByteArrayOutputStream();
				new DataOutputStream(out).writeBoolean(entryExists);
				reply = out.toByteArray();
				out.close();
				break;
			case BFTMapRequestType.TAB_CREATE_CHECK:
				tableName = new DataInputStream(in).readUTF();
				// logger.debug("Table of Table Key received: " + tableName);
				Map<String, byte[]> table = tableMap.getTable(tableName);
				boolean tableExists = (table != null);
				logger.debug("Table exists: " + tableExists);
				out = new ByteArrayOutputStream();
				new DataOutputStream(out).writeBoolean(tableExists);
				reply = out.toByteArray();
				out.close();
				break;
			}
			return reply;
		} catch (IOException ex) {
			ex.printStackTrace();
			return null;
		}
	}

	@Override
	public byte[] getSnapshot() {
		try {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutput out = new ObjectOutputStream(bos);
			out.writeObject(tableMap);
			out.flush();
			bos.flush();
			out.close();
			bos.close();
			return bos.toByteArray();
		} catch (IOException ex) {
			ex.printStackTrace();
			return new byte[0];
		}
	}

	@Override
	public void installSnapshot(byte[] state) {
		try {

			// serialize to byte array and return
			ByteArrayInputStream bis = new ByteArrayInputStream(state);
			ObjectInput in = new ObjectInputStream(bis);
			tableMap = (MapOfMaps) in.readObject();
			in.close();
			bis.close();

		} catch (ClassNotFoundException ex) {
			ex.printStackTrace();
		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}

}