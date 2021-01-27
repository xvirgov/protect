package com.ibm.pross.server.app.avpss;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AlertLog {

	// Enumeration of possible error conditions
	public static enum ErrorCondition {
		DuplicateMessage,
		InconsistentShare,
		InvalidShareContribution,
		InvalidVerificationVector, 
		BadRebuttal, 
		StateViolation, 
		InvalidProof, 
		InvalidBulkProof, 
		UnrecognizedMessageType, 
		InvalidCiphertext;
	}

	private static final Logger logger = LogManager.getLogger(AlertLog.class);

	// Log of errors
	private final List<SimpleEntry<Integer, ErrorCondition>> alerts = new ArrayList<>();

	public void reportError(final int reporterIndex, final int reportedIndex, final ErrorCondition error) {

		logger.error(reportedIndex + ": " + error);
		
		// Add error report to error log
		alerts.add(new SimpleEntry<Integer, ErrorCondition>(reportedIndex, error));

	}

	public List<SimpleEntry<Integer, ErrorCondition>> getAlerts() {
		return Collections.unmodifiableList(alerts);
	}

}
