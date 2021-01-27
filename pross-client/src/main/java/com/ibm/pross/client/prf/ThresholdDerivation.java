/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.client.prf;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import com.ibm.pross.common.DerivationResult;
import com.ibm.pross.common.EcPseudoRandomFunction;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.shamir.Polynomials;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The client drives OPRF computations or T-OPRF computations against the
 * shareholders
 */
public class ThresholdDerivation implements EcPseudoRandomFunction {

	private static final Logger logger = LogManager.getLogger(ThresholdDerivation.class);

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();
	final public static EcPoint G = curve.getG();

	private final Map<EcPseudoRandomFunction, BigInteger> shareholders = new HashMap<>();
	private final int threshold;

	// The public key of the thresholdized secret
	private final EcPoint publicKey;

	public ThresholdDerivation(final EcPseudoRandomFunction[] shareholders, final int threshold) {
		for (int i = 0; i < shareholders.length; i++) {
			this.shareholders.put(shareholders[i], BigInteger.valueOf(i + 1));
		}
		this.threshold = threshold;
		this.publicKey = computePublicKey(shareholders);
	}
	
	public ThresholdDerivation(final EcPseudoRandomFunction[] shareholders, final int threshold, final EcPoint publicKey) {
		for (int i = 0; i < shareholders.length; i++) {
			this.shareholders.put(shareholders[i], BigInteger.valueOf(i + 1));
		}
		this.threshold = threshold;
		this.publicKey = publicKey;
	}

	protected EcPoint computePublicKey(EcPseudoRandomFunction[] shareholders) {

		// Use interpolation to derive the public key of the overall secret
		// This is the public key of the overall secret (which is thresholdized)

		final List<DerivationResult> results = new ArrayList<>();

		// Send derive operation to each server
		for (EcPseudoRandomFunction shareholder : this.shareholders.keySet()) {
			final EcPoint result = shareholder.getPublicKey();
			results.add(new DerivationResult(this.shareholders.get(shareholder), result));
			if (results.size() >= this.threshold) {
				break;
			}
		}

		final EcPoint totalPublicKey = Polynomials.interpolateExponents(results, threshold, 0);

		return totalPublicKey;
	}

	@Override
	public EcPoint derive(final EcPoint input) {

		final List<DerivationResult> results = new ArrayList<>();

		// Send derive operation to each server
		List<EcPseudoRandomFunction> shareholderList = new ArrayList<>(this.shareholders.keySet());
		Collections.shuffle(shareholderList);
		for (EcPseudoRandomFunction shareholder : shareholderList) {

			final BigInteger shareholderIndex = this.shareholders.get(shareholder);

			try {
				final EcPoint result = shareholder.derive(input);
				results.add(new DerivationResult(shareholderIndex, result));

				if (results.size() >= this.threshold) {
					break; // Exit when we have enough valid responses
				}

			} catch (Exception e) {
				logger.info("Failed to get valid response from shareholder [" + shareholderIndex + "]");

			}

		}

		// Combine shares
		logger.info("  Recovering secret from shares...");

		// Randomize which shareholders are used
		final List<DerivationResult> ranomizedList = new ArrayList<>(new HashSet<>(results));
		final EcPoint totalResult = Polynomials.interpolateExponents(ranomizedList, threshold, 0);
		logger.info(" done.");

		return totalResult;
	}

	@Override
	public EcPoint getPublicKey() {
		return this.publicKey;
	}

}
