package com.ibm.pross.server.messages.payloads.apvss;

import com.ibm.pross.common.util.pvss.PolynomialSharing;
import com.ibm.pross.server.messages.Payload;

public class PolynomialSharingPayload extends Payload {
    public PolynomialSharingPayload(PolynomialSharing polynomialSharing) {
        super(OpCode.FS, polynomialSharing);
    }
}
