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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;

import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Example replica that implements a BFT replicated service (a logger).
 * It maintains a consistent state which is the CRC of all messages seen.
 * 
 * @author jresch
 */

public final class LoggerServer extends DefaultSingleRecoverable {

    private static final Logger logger = LogManager.getLogger(LoggerServer.class);

	CRC32 crc32 = new CRC32();
	private String message = "";
	private int iterations = 0;

	public LoggerServer(int id) {
		new ServiceReplica(id, this, this);
	}

	@Override
	public byte[] appExecuteUnordered(byte[] command, MessageContext msgCtx) {
		iterations++;

		logger.info("(" + iterations + ") Counter message value: " + this.message);
		return this.message.getBytes(StandardCharsets.UTF_8);
	}

	@Override
	public byte[] appExecuteOrdered(byte[] command, MessageContext msgCtx) {
		iterations++;
		
		crc32.update(command);

		String message = new String(command, StandardCharsets.UTF_8);

		logger.info("(" + iterations + ") Message was added. Current value = " + message);
		logger.info("      Current state: " + crc32.getValue());

		this.message = message;

		return message.getBytes(StandardCharsets.UTF_8);

	}

	public static void main(String[] args) {
		if (args.length < 1) {
			logger.info("Use: java CounterServer <processId>");
			System.exit(-1);
		}
		new LoggerServer(Integer.parseInt(args[0]));
	}
	
    @Override
    public void installSnapshot(byte[] state) {
        try {
            logger.info("setState called");
            ByteArrayInputStream bis = new ByteArrayInputStream(state);
            ObjectInput in = new ObjectInputStream(bis);
            
            long crcState = 0x00000000FFFFFFFF & in.readInt();
            this.crc32 = new CRC32();
            
            Class<?> clazz = this.crc32.getClass();
            Field field = clazz.getDeclaredField("crc");
            field.setAccessible(true);
            field.set(this.crc32, (int) crcState);
            
            
            in.close();
            bis.close();
        } catch (Exception e) {
            System.err.println("[ERROR] Error deserializing state: "
                    + e.getMessage());
        }
    }

    @Override
    public byte[] getSnapshot() {
        try {
            logger.info("getState called");
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutput out = new ObjectOutputStream(bos);
            out.writeInt((int)crc32.getValue());
            out.flush();
            bos.flush();
            out.close();
            bos.close();
            return bos.toByteArray();
        } catch (IOException ioe) {
            System.err.println("[ERROR] Error serializing state: "
                    + ioe.getMessage());
            return "ERROR".getBytes();
        }
    }
}
