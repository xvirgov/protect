package com.ibm.pross.server.messages.payloads.apvss;

import com.ibm.pross.common.util.pvss.ProactiveRsaSharing;
import com.ibm.pross.server.messages.Payload;

public class ProactiveRsaPayload extends Payload {
    public ProactiveRsaPayload(ProactiveRsaSharing proactiveRsaSharing) {
        super(OpCode.RSA, proactiveRsaSharing);
    }
}
