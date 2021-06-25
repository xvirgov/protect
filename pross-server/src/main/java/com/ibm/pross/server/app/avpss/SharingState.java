package com.ibm.pross.server.app.avpss;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import com.ibm.pross.common.util.pvss.PolynomialSharing;
import com.ibm.pross.common.util.pvss.ProactiveRsaSharing;
import org.apache.commons.codec.binary.Hex;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
import com.ibm.pross.common.util.crypto.zkp.splitting.ZeroKnowledgeProof;
import com.ibm.pross.common.util.pvss.PublicSharing;
import com.ibm.pross.common.util.shamir.ShamirShare;

public class SharingState {

	// Public Values to verify consistency of sharing
	protected final ZeroKnowledgeProof[] receivedProofs;
	private final SortedMap<Integer, EcPoint> qualifiedProofs;
	private final SortedMap<Integer, EcPoint> verifications;
	private final EcPoint[] sharePublicKeys; // g^s_i for i = 0 to n (inclusive)
	private EcPoint[] feldmanValues; // g^a_i for i = 0 to k-1 (inclusive)

	// Epoch information
	final long epochNumber;

	// Create date of this secret
	private volatile Date creationTime;

	// Tracks if we have sent our public sharing
	private final AtomicBoolean broadcastSharing = new AtomicBoolean(false);

	// Received public sharings
	protected final PublicSharing[] receivedSharings;

	// Our verification vector
	private final AtomicInteger successCount = new AtomicInteger(0);

	// Qualified shareholders
	private volatile SortedMap<Integer, PublicSharing> qualifiedSharings;
	private volatile boolean isQualSetDefined = false;

	// Constructed Shares (x_i)
	private volatile ShamirShare share1;
	private volatile ShamirShare share2;

	// Pedersen commitments to the co-efficients of the combined polynomial
	private volatile EcPoint[] pedersenCommitments;

	// Values used only for RSA
	private volatile RsaSharing rsaSharing;

	// Used to time operation
	private volatile long startTime;
	// Proactive RSA parameters
	private final SortedMap<Long, ProactiveRsaSharing> receivedProactiveRsaSharings;
	private final SortedMap<Long, PolynomialSharing> receivedPolynomialSharings;

	public SharingState(final int n, final int k, final long epochNumber) {
		this.epochNumber = epochNumber;

		/** Variables to track sharing **/
		this.receivedSharings = new PublicSharing[n];
		this.qualifiedSharings = new TreeMap<>();

		/** Variables to track splitting proofs **/
		this.receivedProofs = new ZeroKnowledgeProof[n];
		this.qualifiedProofs = new TreeMap<>();
		this.verifications = new TreeMap<>();
		this.sharePublicKeys = new EcPoint[n + 1]; // position 0 = g^s
		this.feldmanValues = new EcPoint[k];

		/** Variables to track RSA sharing **/
		this.receivedProactiveRsaSharings = new TreeMap<>();
		this.receivedPolynomialSharings = new TreeMap<>();
	}

	public EcPoint[] getFeldmanValues() {
		return feldmanValues;
	}

	public void setFeldmanValues(EcPoint[] feldmanValues) {
		this.feldmanValues = feldmanValues;
	}

	public Date getCreationTime() {
		return creationTime;
	}

	public void setCreationTime(Date creationTime) {
		this.creationTime = creationTime;
	}

	public SortedMap<Integer, PublicSharing> getQualifiedSharings() {
		return qualifiedSharings;
	}

	public void setQualifiedSharings(SortedMap<Integer, PublicSharing> qualifiedSharings) {
		this.qualifiedSharings = qualifiedSharings;
	}

	public boolean isQualSetDefined() {
		return isQualSetDefined;
	}

	public void setQualSetDefined(boolean isQualSetDefined) {
		this.isQualSetDefined = isQualSetDefined;
	}

	public ShamirShare getShare1() {
		return share1;
	}

	public void setShare1(ShamirShare share1) {
		this.share1 = share1;
	}

	public ShamirShare getShare2() {
		return share2;
	}

	public String getShare1Hash() {
		try {
			if (getShare1() == null) {
				return "[SHARE DELETED]";
			} else {
				return Hex.encodeHexString(MessageDigest.getInstance(CommonConfiguration.HASH_ALGORITHM)
						.digest(getShare1().getY().toByteArray()));
			}
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public void setShare2(ShamirShare share2) {
		this.share2 = share2;
	}

	public EcPoint[] getPedersenCommitments() {
		return pedersenCommitments;
	}

	public void setPedersenCommitments(EcPoint[] pedersenCommitments) {
		this.pedersenCommitments = pedersenCommitments;
	}

	public long getStartTime() {
		return startTime;
	}

	public void setStartTime(long startTime) {
		this.startTime = startTime;
	}

	public ZeroKnowledgeProof[] getReceivedProofs() {
		return receivedProofs;
	}

	public SortedMap<Integer, EcPoint> getQualifiedProofs() {
		return qualifiedProofs;
	}

	public SortedMap<Integer, EcPoint> getVerifications() {
		return verifications;
	}

	public EcPoint[] getSharePublicKeys() {
		return sharePublicKeys;
	}

	public long getEpochNumber() {
		return epochNumber;
	}

	public AtomicBoolean getBroadcastSharing() {
		return broadcastSharing;
	}

	public PublicSharing[] getReceivedSharings() {
		return receivedSharings;
	}

	public AtomicInteger getSuccessCount() {
		return successCount;
	}

	public RsaSharing getRsaSharing() {
		return rsaSharing;
	}

	public void setRsaSharing(RsaSharing rsaSharing) {
		this.rsaSharing = rsaSharing;
	}

	public void addProactiveRsaSharing(long senderIndex, ProactiveRsaSharing proactiveRsaSharing) {
		this.receivedProactiveRsaSharings.put(senderIndex, proactiveRsaSharing);
	}

	public SortedMap<Long, ProactiveRsaSharing> getReceivedProactiveRsaSharings() {
		return receivedProactiveRsaSharings;
	}

	public void addPolynomialSharing(long senderIndex, PolynomialSharing polynomialSharing) {
		this.receivedPolynomialSharings.put(senderIndex, polynomialSharing);
	}

	public SortedMap<Long, PolynomialSharing> getReceivedPolynomialSharings() {
		return receivedPolynomialSharings;
	}
}
