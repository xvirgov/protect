package com.ibm.pross.server.channel.bft;

import com.ibm.pross.server.app.MessageStatusCli;
import com.ibm.pross.server.channel.ChannelSender;
import com.ibm.pross.server.messages.SignedMessage;
import com.ibm.pross.server.util.MessageSerializer;

import bftsmart.tom.ServiceProxy;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BftChannelSender implements ChannelSender {

	private final ServiceProxy serviceProxy;

	private static final Logger logger = LogManager.getLogger(BftChannelSender.class);

	public BftChannelSender(int senderId) {
		this.serviceProxy = new ServiceProxy(senderId);
	}

	@Override
	public void broadcast(SignedMessage message) {

		// Serialize message to bytes
		byte[] serializedMessage = MessageSerializer.serializeSignedMessage(message);

		// Send total ordered message
		//logger.info("Sending message: " + HexUtil.binToHex(serializedMessage));
		this.serviceProxy.invokeOrdered(serializedMessage);

		// Give some time for everyone to process the message
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			throw new RuntimeException("interrupted", e);
		}

	}

}
