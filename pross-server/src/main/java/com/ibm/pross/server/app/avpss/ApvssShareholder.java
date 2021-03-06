package com.ibm.pross.server.app.avpss;

import java.math.BigInteger;
import java.util.*;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import com.ibm.pross.common.DerivationResult;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.kyber.KyberShareholder;
import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierPrivateKey;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaShareholder;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaProactiveSharing;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
import com.ibm.pross.common.util.crypto.zkp.splitting.ZeroKnowledgeProof;
import com.ibm.pross.common.util.crypto.zkp.splitting.ZeroKnowledgeProver;
import com.ibm.pross.common.util.pvss.*;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.app.avpss.channel.FifoAtomicBroadcastChannel;
import com.ibm.pross.server.app.avpss.exceptions.DuplicateMessageReceivedException;
import com.ibm.pross.server.app.avpss.exceptions.ErrorConditionException;
import com.ibm.pross.server.app.avpss.exceptions.InconsistentShareException;
import com.ibm.pross.server.app.avpss.exceptions.InvalidCiphertextException;
import com.ibm.pross.server.app.avpss.exceptions.InvalidZeroKnowledgeProofException;
import com.ibm.pross.server.app.avpss.exceptions.StateViolationException;
import com.ibm.pross.server.app.avpss.exceptions.UnrecognizedMessageTypeException;
import com.ibm.pross.server.messages.Message;
import com.ibm.pross.server.messages.Payload.OpCode;
import com.ibm.pross.server.messages.payloads.apvss.PolynomialSharingPayload;
import com.ibm.pross.server.messages.payloads.apvss.ProactiveRsaPayload;
import com.ibm.pross.server.messages.payloads.apvss.PublicSharingPayload;
import com.ibm.pross.server.messages.payloads.apvss.ZkpPayload;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ApvssShareholder {

    private volatile long startCommunication;

    // Group Constants
    public static final EcCurve curve = CommonConfiguration.CURVE;
    public static final EcPoint g = CommonConfiguration.g;
    public static final EcPoint h = CommonConfiguration.h;
    private static final Logger logger = LogManager.getLogger(ApvssShareholder.class);
    // Error log (useful for testing and for identifying problem shareholders)
    protected final AlertLog alertLog = new AlertLog();
    // The set of peer shareholder's keys
    private final KeyLoader keyLoader;
    // Channel-related variables
    private final FifoAtomicBroadcastChannel channel;
    private final AtomicLong currentMessageId = new AtomicLong(0);

    // Our message processing thread
    private final Thread messageProcessingThread;
    private final AtomicBoolean stopped = new AtomicBoolean(true);

    // Our timer task for doing proactive refresh
    private final Timer timer = new Timer(true);

    /********************** Misc Info ******************************/
    // The unique name for this secret
    private final String secretName;
    /*****************************************************************/

    // The index of this shareholder (ourself) (one is the base index)
    // This shareholder will hold the share at f(index)
    private final int index;
    // The number of shareholders
    private final int n;
    // The recovery threshold of the secret
    private final int k;
    // Used to misbehave
    private final boolean sendValidCommitments;
    // Track each epoch separately
    private final Map<Long, SharingState> sharingStates = new ConcurrentHashMap<>();
    private final AtomicLong currentEpoch = new AtomicLong(0);
    private final AtomicLong nextEpoch = new AtomicLong(0);
    private final AtomicLong[] shareholderMessageCounts;
    // How the secret was established
    private volatile SharingType sharingType;
    private AtomicBoolean enabled = new AtomicBoolean(true);
    // Used to hold an initial share of a secret (to supported stored secrets)
    private volatile BigInteger storedShareOfSecret = null;

    private RsaProactiveSharing rsaProactiveSharing;
    private ProactiveRsaShareholder proactiveRsaShareholder;
    private KyberShareholder kyberShareholder;

    private final int refreshFrequency;

    public ApvssShareholder(final String secretName, final KeyLoader keyLoader,
                            final FifoAtomicBroadcastChannel channel, final int index, final int n, final int k, final boolean sendValidCommitments) {
        this(secretName, keyLoader, channel, index, n, k, sendValidCommitments, 60);
    }

    public ApvssShareholder(final String secretName, final KeyLoader keyLoader,
                            final FifoAtomicBroadcastChannel channel, final int index, final int n, final int k, final int refreshFrequency) {
        this(secretName, keyLoader, channel, index, n, k, true, refreshFrequency);
    }

    public ApvssShareholder(final String secretName, final KeyLoader keyLoader,
                            final FifoAtomicBroadcastChannel channel, final int index, final int n, final int k,
                            final boolean sendValidCommitments, final int refreshFrequency) {

        this.refreshFrequency = refreshFrequency;

        this.secretName = secretName;

        // Start first epoch
        this.sharingStates.put(currentEpoch.get(), new SharingState(n, k, 0));

        // Track message counts from senders
        this.shareholderMessageCounts = new AtomicLong[n];
        for (int i = 0; i < n; i++) {
            this.shareholderMessageCounts[i] = new AtomicLong(0);
        }

        this.sendValidCommitments = sendValidCommitments;

        /** Values unique to ourselves **/
        this.index = index;

        /** Public shared configuration parameters **/
        this.keyLoader = keyLoader;
        this.channel = channel;
        this.n = n;
        this.k = k; // reconstruction threshold (usually f_S + 1)

        this.messageProcessingThread = createMessageProcessingThread(this.channel);
    }

    public Thread createMessageProcessingThread(final FifoAtomicBroadcastChannel channel) {
        return new Thread(new Runnable() {

            @Override
            public void run() {
                while (!ApvssShareholder.this.stopped.get()) {
                    while (channel.getMessageCount() > currentMessageId.get()) {
//                        logger.info("A message is being retrieved from queue");
                        messageIsAvailable();
                    }

                    try {
                        synchronized (channel) {
                            channel.wait(100);
                        }
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }
            }
        }, "Shareholder-Thread-" + this.index);
    }

    /**
     * A message is available on the queue, get it and deliver it for processing
     */
    private synchronized void messageIsAvailable() {

        final long messageId = this.currentMessageId.incrementAndGet();
        final Message message = this.channel.getMessage(messageId);

        // TODO: Remove this debugging text
        // long messageCount = this.channel.getMessageCount();
        // logger.error(messageCount + ";" + messageId);

        // Deliver only if this message is relevant for the given epoch and secret
        final String channelName = this.secretName;
        if (message.isRecipient(channelName)) {
//            logger.info("DKG app processing message #" + messageId);
            deliver(message);
        }
    }

    /**
     * Deliver a message received on the FIFO-AB channel to the correct method
     * <p>
     * If any error condition occurs, an entry will be added to the alert log
     *
     * @param message
     */
    private synchronized void deliver(final Message message) {

        if (message instanceof Message) {

            final OpCode opcode = ((Message) message).getPayload().getOpcode();

            // Track how many messages have been received from this shareholder
            final int senderId = message.getSenderIndex();
            final long messageCount = this.shareholderMessageCounts[senderId - 1].getAndIncrement();
            final long senderEpoch = messageCount / 2;

            try {

                // Make sure the sender hasn't gotten too far ahead (we should have the previous
                // sharing already)
                if (senderEpoch > this.nextEpoch.get()) {
                    // throw new StateViolationException("Sender is getting too far ahead");
                }

                switch (opcode) {
                    case RSA:
                        deliverRsaSharing(senderEpoch, (Message) message);
                        break;
                    case FS:
                        deliverPolynomialSharing(senderEpoch, (Message) message);
                        break;
                    case PS:
                        deliverPublicSharing(senderEpoch, (Message) message);
                        break;
                    case ZK:
                        deliverProofMessage(senderEpoch, (Message) message);
                        break;
                    case NOOP:
                        // Do nothing
                        break;
                    default:
                        throw new UnrecognizedMessageTypeException();
                }
            } catch (final ErrorConditionException e) {
                this.alertLog.reportError(this.index, message.getSenderIndex(), e.getErrorCondition());
            }

        }
    }

    public void start(boolean sendContributions) {
        if (this.stopped.compareAndSet(true, false)) {

            if (sendContributions) {
                // First broadcast our commitment and share contributions to the channel
                broadcastPublicSharing(0);
            }

            // Start the shareholder (await and process messages)
            this.messageProcessingThread.start();
        }
    }

    public void stop() {

        if (this.stopped.compareAndSet(false, true)) {

            // Wake the sleeping threads
            synchronized (this.channel) {
                this.channel.notifyAll();
            }

            try {
                this.messageProcessingThread.join();
            } catch (InterruptedException e) {
                // Interrupted
            }
        }
    }

    private long getCurrentEpoch() {
        return currentEpoch.get();
    }

    public SharingState getSharing(final long epochNumber) {
        synchronized (this.sharingStates) {
            this.sharingStates.putIfAbsent(epochNumber, new SharingState(n, k, epochNumber));
            return this.sharingStates.get(epochNumber);
        }
    }

    private SharingState getCurrentSharing() {
        return getSharing(getCurrentEpoch());
    }

    /**
     * Send out initial message containing our Public Sharing (privately encrypted
     * shares to each peer shareholder, proofs of correctness and our Pedersen
     * commitments. This will start the DKG protocol based on APVSS, and it will be
     * driven to completion.
     */
    public boolean broadcastPublicSharing(final long epoch) {

        // Get sharing state for the current epoch
        final SharingState sharingState = getSharing(epoch);
        long start, end;

        if (sharingState.getBroadcastSharing().compareAndSet(false, true)) {

            sharingState.setStartTime(System.nanoTime());
            start = System.nanoTime();

            // Get shareholder public encryption keys
            final PaillierPublicKey[] publicKeys = new PaillierPublicKey[n];
            for (int i = 1; i <= n; i++) {
                publicKeys[i - 1] = (PaillierPublicKey) this.keyLoader.getEncryptionKey(i);
//                logger.info(publicKeys[i - 1].toString());
            }

            // Create Public Sharing (if first DKG use random, otherwise use share)
            final PublicSharingGenerator generator = new PublicSharingGenerator(this.n, this.k);
            final PublicSharing publicSharing;
            if (epoch == 0) {
                logger.info("Starting DKG operation!");
                if (storedShareOfSecret == null) {
                    // No share was stored, do a DKG of a random value
                    publicSharing = generator.shareRandomSecret(publicKeys);
                    this.sharingType = SharingType.PEDERSEN_DKG;
                } else {
                    // A share was pre-stored, do a DKG using this value
                    publicSharing = generator.shareSecret(storedShareOfSecret, publicKeys);
                    this.storedShareOfSecret = null; // Wipe it for proactive security
                    this.sharingType = SharingType.STORED;
                }
            } else {
                if (getSharing(epoch - 1).getShare1() != null) {
                    final BigInteger share1 = getSharing(epoch - 1).getShare1().getY();
                    final BigInteger share2 = getSharing(epoch - 1).getShare2().getY();
                    publicSharing = generator.shareSecretAndRandomness(share1, share2, publicKeys);
                } else {
                    // Share was deleted, send a null contribution
                    publicSharing = null;
                }
            }

            end = System.nanoTime();
            logger.info("PerfMeas:EciesBroadcastSharingEnd:" + (end - start));
//            logger.info("BBBBBB SENDING FIRST MESSAGE");

            // Create a message
            final PublicSharingPayload payload = new PublicSharingPayload(publicSharing);
            final String channelName = this.secretName;
            final Message publicSharingMessage = new Message(channelName, this.index, payload);
//            logger.info(publicSharingMessage);

            this.setStartCommunication(System.nanoTime());
            this.channel.send(publicSharingMessage);

            return true;
        } else {
            return false; // Already started
        }
    }

    public boolean refreshRsaSharing(final long epoch) {
        long start, end;

        logger.info("Proactive-RSA refresh round started...");

        start = System.nanoTime();
        // Get sharing state for the current epoch
        final SharingState sharingState = getSharing(epoch);

        if (!sharingState.getBroadcastSharing().compareAndSet(false, true))
            return false; // already started

        sharingState.setStartTime(System.nanoTime());

        // Get shareholder public encryption keys
        final PaillierPublicKey[] publicKeys = new PaillierPublicKey[n];
        for (int i = 1; i <= n; i++) {
            publicKeys[i - 1] = (PaillierPublicKey) this.keyLoader.getEncryptionKey(i);
//            logger.info(publicKeys[i - 1].toString());
        }


//        // Create Public Sharing (if first DKG use random, otherwise use share)
//        final PublicSharingGenerator generator = new PublicSharingGenerator(this.n, this.k);
//        final PublicSharing publicSharing;
//        if (epoch == 0) {
//            logger.info("Starting DKG operation!");
//            if (storedShareOfSecret == null) {
//                // No share was stored, do a DKG of a random value
//                publicSharing = generator.shareRandomSecret(publicKeys);
//                this.sharingType = SharingType.PEDERSEN_DKG;
//            } else {
//                // A share was pre-stored, do a DKG using this value
//                publicSharing = generator.shareSecret(storedShareOfSecret, publicKeys);
//                this.storedShareOfSecret = null; // Wipe it for proactive security
//                this.sharingType = SharingType.STORED;
//            }
//        } else {
//            if (getSharing(epoch - 1).getShare1() != null) {
//                final BigInteger share1 = getSharing(epoch - 1).getShare1().getY();
//                final BigInteger share2 = getSharing(epoch - 1).getShare2().getY();
//                publicSharing = generator.shareSecretAndRandomness(share1, share2, publicKeys);
//            } else {
//                // Share was deleted, send a null contribution
//                publicSharing = null;
//            }
//        }
//

//        publicSharing = generator.shareRandomSecret(publicKeys);

        // Create a message
//        final PublicSharingPayload payload = new PublicSharingPayload(publicSharing);
//        final PublicSharingPayload payload = new PublicSharingPayload(publicSharing);


//        final PublicSharingPayload payload = new PublicSharingPayload(publicSharing);
//        final String channelName = this.secretName;
//        final Message publicSharingMessage = new Message(channelName, this.index, payload);
//        logger.info(publicSharingMessage);
//        this.channel.send(publicSharingMessage);

//        final ProactiveRsaSharingGenerator proactiveRsaSharingGenerator = new ProactiveRsaSharingGenerator();
        ProactiveRsaSharing proactiveRsaSharing = ProactiveRsaSharingGenerator.refreshAdditiveShares(index, proactiveRsaShareholder);
//        logger.info(proactiveRsaSharing.getI());
//        logger.info(proactiveRsaSharing.getD_i_j());
//        logger.info(proactiveRsaSharing.getW_i_j());
//        logger.info(proactiveRsaSharing.getD_i_pub());
        final ProactiveRsaPayload proactiveRsaPayload = new ProactiveRsaPayload(ProactiveRsaSharingGenerator.encryptAdditiveShares(proactiveRsaSharing, publicKeys));

//        logger.info("RSA proactive sharing was refreshed");
//        logger.info("Stopped: " + stopped);

        // Create a message
        final Message publicSharingMessage = new Message(this.secretName, this.index, proactiveRsaPayload);

        end = System.nanoTime();
        logger.info("PerfMeas:RsaRefreshAdditiveEnd:" + (end - start));

        this.setStartCommunication(System.nanoTime());
        this.channel.send(publicSharingMessage);

        return true;
    }

    /**
     * Process received PublicSharing and update qual set
     *
     * @param senderEpoch
     * @param message
     * @throws DuplicateMessageReceivedException
     * @throws InvalidCiphertextException
     * @throws InconsistentShareException
     * @throws StateViolationException
     */
    protected synchronized void deliverPublicSharing(final long senderEpoch, final Message message)
            throws DuplicateMessageReceivedException, InvalidCiphertextException, InconsistentShareException,
            StateViolationException {

        // Get sharing state for the current epoch
        final SharingState sharingState = getSharing(senderEpoch);
        final int successes = sharingState.getSuccessCount().incrementAndGet();
        if (successes > k) {
            return;
        }

//        logger.info("BBBBBB FIRST MESSAGE RECEIVED");

        // A DKG is starting, broadcast sharing if we have not already done so
        if ((senderEpoch == 0) && (this.currentEpoch.get() == 0) && (this.getSecretPublicKey() == null)) {
            if (!sharingState.getBroadcastSharing().get()) {
                broadcastPublicSharing(0); // First DKG triggered by someone else, all other proactive by us
            }
        }

        // Check if we've seen one of these already
        final int senderIndex = message.getSenderIndex();
        if (sharingState.getReceivedSharings()[senderIndex - 1] != null) {
            throw new DuplicateMessageReceivedException("duplicate share contribution");
        }

        // Extract the payload
        final PublicSharing publicSharing = (PublicSharing) message.getPayload().getData();

        if (publicSharing == null) {
            // This shareholder lost a share, ignore
            return;
        }

        // Save it
        sharingState.getReceivedSharings()[senderIndex - 1] = publicSharing;

        // Ensure sharing matches our n and t
        if (publicSharing.getNumShares() != this.n) {
            throw new InconsistentShareException("incorrect n");
        }
        if (publicSharing.getThreshold() != this.k) {
            throw new InconsistentShareException("incorrect k");
        }

        // Get shareholder public encryption keys
        final PaillierPublicKey[] shareholderKeys = new PaillierPublicKey[n];
        for (int i = 1; i <= this.n; i++) {
            shareholderKeys[i - 1] = (PaillierPublicKey) this.keyLoader.getEncryptionKey(i);
        }

        // Verify the shares are correct
        if (!publicSharing.verifyAllShares(shareholderKeys)) {
            throw new InvalidCiphertextException("Public Sharing was not valid");
        }

        // Verify consistency with the previous commitment g_^{s_i} * h^{r_i}
        if (senderEpoch > 0) {
            final EcPoint secretCommitment = publicSharing.getSecretCommitment();

            final SharingState previousSharing = this.getSharing(senderEpoch - 1);
            final EcPoint previousShareCommitment = PublicSharingGenerator.interpolatePedersonCommitments(
                    BigInteger.valueOf(senderIndex), previousSharing.getPedersenCommitments());

            if (!secretCommitment.equals(previousShareCommitment)) {
                throw new InconsistentShareException("Shareholder sent an invalid sharing");
            }
        }

        // It is valid, increment success count
        if (successes <= k) {
            // We are still building the qual set, add it
            sharingState.getQualifiedSharings().put(senderIndex, publicSharing);
        }

        if (successes == this.k) {
            // We have reached a threshold to proceed to next phase
            logger.info("PerfMeas:EciesRefreshCommunicationOne:" + (System.nanoTime()-this.getStartCommunication()));
            assembleCombinedShareByInterpolation(senderEpoch);
        }
    }

    /**
     * Complete the DKG by combining all the PVSSs in Qual (via interpolation,
     * rather than summation)
     */
    private synchronized void assembleCombinedShareByInterpolation(final long senderEpoch) {

        logger.info("assembleCombinedShareByInterpolation");

        long start, end;
        start = System.nanoTime();

        // Get sharing state for the current epoch
        final SharingState sharingState = getSharing(senderEpoch);

        // Determine list of contributors
        final List<Integer> contributors = new ArrayList<>(sharingState.getQualifiedSharings().keySet());
        Collections.sort(contributors);
        final BigInteger[] xCoords = contributors.stream().map(i -> BigInteger.valueOf(i)).toArray(BigInteger[]::new);

        // final BigInteger[] xCoords =
        // sharingState.getQualifiedSharings().keySet().stream()
        // .map(i -> BigInteger.valueOf(i)).toArray(BigInteger[]::new);

        // Start counters at zero
        BigInteger share1Y = BigInteger.ZERO;
        BigInteger share2Y = BigInteger.ZERO;
        EcPoint[] combinedPedersenCommitments = new EcPoint[this.k];
        for (int i = 0; i < this.k; i++) {
            combinedPedersenCommitments[i] = EcPoint.pointAtInfinity;
        }

        // Use our decryption key to access our shares
        final PaillierPrivateKey decryptionKey = (PaillierPrivateKey) this.keyLoader.getDecryptionKey();

        // Iterate over every public sharing in qual
        for (final Integer contributor : contributors) {

            final BigInteger j = BigInteger.valueOf(contributor);
            final PublicSharing sharing = sharingState.getQualifiedSharings().get(contributor);

            // Decrypt our shares
            final ShamirShare share1 = sharing.accessShare1(index - 1, decryptionKey);
            final ShamirShare share2 = sharing.accessShare2(index - 1, decryptionKey);

            // Get the commitments
            final EcPoint[] commitments = sharing.getPedersenCommitments();

            // Compute lagrange co-efficient
            final BigInteger l = Polynomials.interpolatePartial(xCoords, BigInteger.ZERO, j, curve.getR());

            // Add the shares to our running sum
            share1Y = share1Y.add(share1.getY().multiply(l)).mod(curve.getR());
            share2Y = share2Y.add(share2.getY().multiply(l)).mod(curve.getR());

            // Add Pedersen commitments to our running sum
            for (int i = 0; i < this.k; i++) {
                final EcPoint interpolatedCommitment = curve.multiply(commitments[i], l);
                combinedPedersenCommitments[i] = curve.addPoints(combinedPedersenCommitments[i],
                        interpolatedCommitment);
            }
        }

        // We have our shares
        sharingState.setShare1(new ShamirShare(BigInteger.valueOf(this.index), share1Y));
        sharingState.setShare2(new ShamirShare(BigInteger.valueOf(this.index), share2Y));

        // We have our Pedersen commitments
        sharingState.setPedersenCommitments(combinedPedersenCommitments);
        end = System.nanoTime();
        logger.info("PerfMeas:EciesAssembleShareEnd:" + (end - start));

        // Broadcast ZKP of a splitting
        broadcastZkp(senderEpoch);

        sharingState.setQualSetDefined(true);

        final long shareEnd = System.nanoTime();
        final long startTime = sharingState.getStartTime();
        logger.info("Time to establish share:             "
                + (((double) (shareEnd - startTime)) / 1_000_000.0) + " ms");
    }

    protected synchronized void deliverRsaSharing(final long senderEpoch, final Message message) throws DuplicateMessageReceivedException, InconsistentShareException {

        final SharingState sharingState = getSharing(senderEpoch);

        // perform checks
        final int senderIndex = message.getSenderIndex();

        if (sharingState.getReceivedProactiveRsaSharings().get((long) senderIndex) != null) {
            throw new DuplicateMessageReceivedException("duplicate share contribution");
        }

        // Extract the payload
        final ProactiveRsaSharing proactiveRsaSharing = (ProactiveRsaSharing) message.getPayload().getData();

        if (proactiveRsaSharing == null) {
            // This shareholder lost a share, ignore
            return;
        }

        // Ensure sharing matches our n and t
        if (proactiveRsaSharing.getD_i_j().size() != this.n) {
            throw new InconsistentShareException("incorrect number of additive shares");
        }
        if (proactiveRsaSharing.getW_i_j().size() != this.n) {
            throw new InconsistentShareException("incorrect number of verification shares");
        }

        // Verify consistency
        BigInteger d_i_pub = proactiveRsaSharing.getD_i_pub().getY();
        BigInteger d_i_pub_i = proactiveRsaSharing.getD_i_pub().getX();

        if(!d_i_pub_i.equals(BigInteger.valueOf(senderIndex)))
            throw new RuntimeException("Inconsistent proactive RSA sharing");


        if(this.proactiveRsaShareholder == null) { // TODO do this better: wait until store was processed on every server
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        BigInteger g = this.proactiveRsaShareholder.getProactiveRsaPublicParameters().getG();
        BigInteger modulus = this.proactiveRsaShareholder.getProactiveRsaPublicParameters().getPublicKey().getModulus();
        List<SecretShare> w_i_j = proactiveRsaSharing.getW_i_j();
        BigInteger newVerificationValue = g.modPow(d_i_pub, modulus).multiply(w_i_j.stream().map(SecretShare::getY).reduce(BigInteger::multiply).get()).mod(modulus);
        BigInteger w = this.proactiveRsaShareholder.getProactiveRsaPublicParameters().getW().get(senderIndex-1).getY();

        if(!w.equals(newVerificationValue))
            throw new RuntimeException("Validation of generated additive shares failed for server " + senderIndex);

        logger.info("Additive shares from server " + senderIndex + " were verified");

        // Save it
        sharingState.addProactiveRsaSharing(senderIndex, proactiveRsaSharing);

        // TODO-rsa verify that shares are correct with previous sharing

        // wait for all some time if not all received, reconstruct failed nodes
        final int successes = sharingState.getSuccessCount().incrementAndGet();
        if (successes == this.n) {
            logger.info("PerfMeas:RsaRefreshCommunicationOne:" + (System.nanoTime()-this.getStartCommunication()));
            assembleAdditiveShare(senderEpoch);
            if (!sharingState.getSuccessCount().compareAndSet(this.n, 0))
                throw new RuntimeException("Unexpected error while refreshing atomic success counter"); // TODO-thesis fix this, we should at least use separate atomic counters for secrets
        }
//        else {
//            // wait
//            // or reconstruct
//        }

    }

    private synchronized void assembleAdditiveShare(final long senderEpoch) {

        long start, end;
        start = System.nanoTime();

        // Get sharing state for the current epoch
        final SharingState sharingState = getSharing(senderEpoch);

        BigInteger new_d_pub = this.proactiveRsaShareholder.getProactiveRsaPublicParameters().getD_pub();
        BigInteger new_d_i = BigInteger.ZERO;

        // Use our decryption key to access our shares
        final PaillierPrivateKey decryptionKey = (PaillierPrivateKey) this.keyLoader.getDecryptionKey();

        BigInteger modulus = this.proactiveRsaShareholder.getProactiveRsaPublicParameters().getPublicKey().getModulus();
        BigInteger g = this.proactiveRsaShareholder.getProactiveRsaPublicParameters().getG();

        List<SecretShare> newW = new ArrayList<>();

        // Compute new d_pub and d_i
        for (int i = 0; i < this.n; i++) {
            ProactiveRsaSharing receivedProactiveSharings = sharingState.getReceivedProactiveRsaSharings().get((long) i + 1);
            BigInteger d_i_j = PaillierCipher.decrypt(decryptionKey, receivedProactiveSharings.getD_i_j().get(this.index - 1).getY());
            BigInteger w_i_j = receivedProactiveSharings.getW_i_j().get(this.index - 1).getY();

//            System.out.println("FROM " + (i+1) + " to "+ index + " decrypting: " +  receivedProactiveSharings.getD_i_j().get(this.index - 1).getY() + " ecrypted: " + d_i_j);

            BigInteger w_j = BigInteger.ONE;
            for(int j = 0; j < this.n; j++) {
                w_j = w_j.multiply(sharingState.getReceivedProactiveRsaSharings().get((long) j + 1).getW_i_j().get(i).getY());
            }

            newW.add(new SecretShare(BigInteger.valueOf(i+1), w_j.mod(modulus)));

            if(!w_i_j.equals(g.modPow(d_i_j, modulus))) { // TODO-thesis this should be moved before we try to assemble
//                logger.info("G: " + g);
//                logger.info("MODULUS: " + modulus);
//                logger.info("W_I_J FROM " + (i+1) + " to "+ index + " received " + w_i_j);
//                logger.info("D_I_J FROM " + (i+1) + " to "+ index + " received " + d_i_j);
//                logger.info("G^{D_I_J} FROM " + (i+1) + " to "+ index + " received " + g.modPow(d_i_j, modulus));
                throw new RuntimeException("Verification of additive share splits failed for a share from agent " + receivedProactiveSharings.getI());
            }
//            else {
//                logger.info( "FROM " + (i+1) + " to "+ index + "YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAS");
//            }
            new_d_i = new_d_i.add(d_i_j);
            new_d_pub = new_d_pub.add(receivedProactiveSharings.getD_i_pub().getY());
        }

        logger.info("Assembled and verified additive shares");

//        logger.info("Calculated new di: " + new_d_i);

        this.proactiveRsaShareholder.setD_i(new_d_i);
        this.proactiveRsaShareholder.getProactiveRsaPublicParameters().setD_pub(new_d_pub);
        this.proactiveRsaShareholder.getProactiveRsaPublicParameters().setW(newW);

        end = System.nanoTime();
        logger.info("PerfMeas:RsaRefreshAssembleAdditiveEnd:" + (end - start));

        broadcastPolynomialSharing(senderEpoch);

//        this.rsaProactiveSharing.setAdditiveShareOfAgent(new_d_i);
//        this.rsaProactiveSharing.
        // set d_i and d_pub

    }

    protected synchronized void deliverPolynomialSharing(final long senderEpoch, final Message message) throws DuplicateMessageReceivedException, InconsistentShareException {

        final SharingState sharingState = getSharing(senderEpoch);

        // perform checks
        final int senderIndex = message.getSenderIndex();

        if (sharingState.getReceivedPolynomialSharings().get((long) senderIndex) != null) {
            throw new DuplicateMessageReceivedException("duplicate share contribution");
        }

        // Extract the payload
        final PolynomialSharing polynomialSharing = (PolynomialSharing) message.getPayload().getData();

        if (polynomialSharing == null) {
            // This shareholder lost a share, ignore
            return;
        }

        // Ensure sharing matches our n and t
        if (polynomialSharing.getShares().size() != this.n) {
            throw new InconsistentShareException("incorrect number of polynomial shares");
        }
//        if (proactiveRsaSharing.getW_i_j().size() != this.n) {
//            throw new InconsistentShareException("incorrect number of verification shares");
//        }

        // Save it
//        sharingState.addProactiveRsaSharing(senderIndex, proactiveRsaSharing);
        sharingState.addPolynomialSharing(senderIndex, polynomialSharing);

        // TODO-rsa verify that shares are correct with previous sharing

        // wait for all some time if not all received, reconstruct failed nodes
        final int successes = sharingState.getSuccessCount().incrementAndGet();
        if (successes == this.n) {
            logger.info("PerfMeas:RsaRefreshCommunicationTwo:" + (System.nanoTime()-this.getStartCommunication()));
            assemblePolynomialShare(senderEpoch);
        }
    }

    private synchronized void assemblePolynomialShare(final long senderEpoch) {
        long start, end;
        start = System.nanoTime();

        BigInteger modulus = this.proactiveRsaShareholder.getProactiveRsaPublicParameters().getPublicKey().getModulus();

        // Get sharing state for the current epoch
        final SharingState sharingState = getSharing(senderEpoch);

        BigInteger newS_i = BigInteger.ZERO;

        // Use our decryption key to access our shares
        final PaillierPrivateKey decryptionKey = (PaillierPrivateKey) this.keyLoader.getDecryptionKey();

        List<SecretShare> decryptedShares = new ArrayList<>();
        List<List<SecretShare>> newB = new ArrayList<>();
        for (int i = 0; i < this.n; i++) {
            BigInteger decryptedShare = PaillierCipher.decrypt(decryptionKey, sharingState.getReceivedPolynomialSharings().get((long) i + 1).getShares().get(this.index - 1).getY());
            decryptedShares.add(new SecretShare(BigInteger.valueOf(i + 1), decryptedShare));
            newS_i = newS_i.add(decryptedShare);

            newB.add(sharingState.getReceivedPolynomialSharings().get((long) i + 1).getB_i());
        }

        List<BigInteger> multipliedFeldmanVerificationValues = new ArrayList<>();
        for (int i = 0; i < this.k; i++) {
            BigInteger accumulator = BigInteger.ONE;
            for (int j = 0; j < this.n; j++) {
                accumulator = accumulator.multiply(newB.get(j).get(i).getY());
            }
            multipliedFeldmanVerificationValues.add(accumulator);
        }

        List<SecretShare> newBAgent = new ArrayList<>();
        for (int i = 0; i < this.n; i++) {
            BigInteger result = BigInteger.ONE;
            for (int j = 0; j < this.k; j++) {
                result = result.multiply(multipliedFeldmanVerificationValues.get(j).modPow(BigInteger.valueOf(i + 1).pow(j), modulus)).mod(modulus);
            }
            newBAgent.add(new SecretShare(BigInteger.valueOf(i+1), result));
        }

        end = System.nanoTime();
        logger.info("PerfMeas:RsaRefreshAssemblePolynomialEnd:" + (end - start));
        final long startTime = sharingState.getStartTime();
        final long endVerification = System.nanoTime();
        logger.info("PerfMeas:RsaRefreshTotalEnd:" + (endVerification - startTime));

        logger.info("New shamir secret share was computed");

        this.proactiveRsaShareholder.setS_i(newS_i);
        this.proactiveRsaShareholder.setS(decryptedShares);
        this.proactiveRsaShareholder.getProactiveRsaPublicParameters().setB(newB);
        this.proactiveRsaShareholder.getProactiveRsaPublicParameters().setbAgent(newBAgent);

        logger.info("Proactive refresh of RSA secret was successful for new epoch " + currentEpoch.getAndIncrement());
        logger.info("Scheduling next proactive refresh in " + this.getRefreshFrequency() + " seconds");

        final int refreshPeriodMillis = this.getRefreshFrequency() * 1000;
        this.timer.schedule(new RefreshTask(), refreshPeriodMillis);

//        BigInteger new_d_pub = this.proactiveRsaShareholder.getProactiveRsaPublicParameters().getD_pub();
//        BigInteger new_d_i = BigInteger.ZERO;
//
//        // Use our decryption key to access our shares
//        final PaillierPrivateKey decryptionKey = (PaillierPrivateKey) this.keyLoader.getDecryptionKey();
//
//
//        // Compute new d_pub and d_i
//        for (int i = 0; i < this.n; i++) {
//            ProactiveRsaSharing receivedProactiveSharings = sharingState.getReceivedProactiveRsaSharings().get((long) i+1);
//            new_d_i = new_d_i.add(PaillierCipher.decrypt(decryptionKey, receivedProactiveSharings.getD_i_j().get(this.index - 1).getY()));
//            new_d_pub = new_d_pub.add(receivedProactiveSharings.getD_i_pub().getY());
//        }
//
//        logger.info("Calculated new di: " + new_d_i);
//
//        this.proactiveRsaShareholder.setD_i(new_d_i);
//        this.proactiveRsaShareholder.getProactiveRsaPublicParameters().setD_pub(new_d_pub);
//
//        broadcastPolynomialSharing(senderEpoch);

//        this.rsaProactiveSharing.setAdditiveShareOfAgent(new_d_i);
//        this.rsaProactiveSharing.
        // set d_i and d_pub

    }

    private void broadcastPolynomialSharing(final long senderEpoch) {
        // create polynomial shares of d_i
//        List<SecretShare> shamirShares = new ArrayList<>();
//        BigInteger additiveShare =  this.proactiveRsaShareholder.getD_i();
//        BigInteger L = this.proactiveRsaShareholder.getProactiveRsaPublicParameters().getL();
//        BigInteger coeffR = this.proactiveRsaShareholder.getProactiveRsaPublicParameters().getCoeffR();
//        BigInteger modulus = this.proactiveRsaShareholder.getProactiveRsaPublicParameters().getPublicKey().getModulus();
//
//        List<BigInteger> coefficients = RandomNumberGenerator.generateRandomArray(BigInteger.valueOf(this.k), coeffR);
//        coefficients.set(0, additiveShare.multiply(L));
//
//        for(int j = 0; j < this.n; j++) {
//            shamirShares.add(Polynomials.evaluatePolynomial(coefficients, BigInteger.valueOf(j + 1), modulus)); // TODO don't use modulus here maybe
//        }
//
        long start, end;
        start = System.nanoTime();
        final PaillierPublicKey[] publicKeys = new PaillierPublicKey[n];
        for (int i = 1; i <= n; i++) {
            publicKeys[i - 1] = (PaillierPublicKey) this.keyLoader.getEncryptionKey(i);
//            logger.info(publicKeys[i - 1].toString());
        }

        PolynomialSharing polynomialSharing = PolynomialSharingGenerator.refreshPolynomialShares(this.index, this.proactiveRsaShareholder);

        // encrypt them
        final PolynomialSharingPayload polynomialSharingPayload = new PolynomialSharingPayload(PolynomialSharingGenerator.encryptPolynomialShares(polynomialSharing, publicKeys));

        end = System.nanoTime();
        logger.info("PerfMeas:RsaRefreshGeneratePolynomialEnd:" + (end - start));

        // send them as a message
        final Message polynomialSharingMessage = new Message(this.secretName, this.index, polynomialSharingPayload);

        this.setStartCommunication(System.nanoTime());
        this.channel.send(polynomialSharingMessage);
    }

    /**
     * Broadcast a ZKP of our shares From these, we can interpolate all the share
     * public keys
     */
    private void broadcastZkp(final long senderEpoch) {
        logger.info("broadcastZkp");
        long start, end;
        start = System.nanoTime();
        // Get sharing state for the current epoch
        final SharingState sharingState = getSharing(senderEpoch);

        final ZeroKnowledgeProof proof;
        if (sharingState.getShare1() != null) {

            // S = g^s_i
            // R = h^r_i
            final BigInteger s = sharingState.getShare1().getY();
            final BigInteger r = sharingState.getShare2().getY();

            // Prove: g^s_i * h^r_i = S (Pedersen commitment)

            if (this.sendValidCommitments) {
                proof = ZeroKnowledgeProver.createProof(s, r);
            } else {
                // Simulate malfunction
                proof = ZeroKnowledgeProver.createProof(s, r.add(BigInteger.ONE));
            }
        } else {
            // Our share is missing, send a null proof
            proof = null;
        }

        end = System.nanoTime();
        logger.info("PerfMeas:EciesGenProofEnd:" + (end - start));

        // Send message out
        final ZkpPayload payload = new ZkpPayload(proof);
        final String channelName = this.secretName;

//        logger.info("BBBBBB SENDING SECOND MESSAGE");
        this.setStartCommunication(System.nanoTime());
        this.channel.send(new Message(channelName, this.index, payload));
    }

    /**
     * Process a proof sent by another shareholder. These will be used to determine
     * the public key of the secret: y = g^x, as well as all the shareholder "share
     * public keys" g^s_i
     *
     * @param senderEpoch
     * @param message
     * @throws DuplicateMessageReceivedException
     * @throws StateViolationException
     * @throws InvalidZeroKnowledgeProofException
     */
    protected synchronized void deliverProofMessage(final long senderEpoch, final Message message)
            throws DuplicateMessageReceivedException, StateViolationException, InvalidZeroKnowledgeProofException {

        // Get sharing state for the current epoch
        final SharingState sharingState = getSharing(senderEpoch);
        if (sharingState.getQualifiedProofs().size() > this.k) {
            return;
        }
//        logger.info("BBBBBB SECOND MESSAGE RECEIVED");

        // Ensure we have completed the sharing
        if (!sharingState.isQualSetDefined()) {
            throw new StateViolationException("Sharing has not yet completed");
        }

        // Check if we've seen one of these already
        final int senderIndex = message.getSenderIndex();
        if (sharingState.getReceivedProofs()[senderIndex - 1] != null) {
            throw new DuplicateMessageReceivedException("duplicate share contribution");
        }

        // The accuser is indicated in the rebuttal message
        final ZeroKnowledgeProof proof = (ZeroKnowledgeProof) message.getPayload().getData();

        if (proof == null) {
            // Sender lost their share, ignore
            return;
        }

//        // maybe worse perf
//        if(sharingState.getVerifications().size() == 0) {
//            BigInteger s = sharingState.getShare1().getY();
////            logger.info("index: " + index);
////            logger.info("s: " + s);
////            logger.info("G: " + curve.getG());
////            logger.info("sG: " + curve.multiply(curve.getG(), s));
//            sharingState.getVerifications().put(index, curve.multiply(CommonConfiguration.g, s));
////            logger.info("sG: " + sharingState.getVerifications());
//        }
//
//        if(senderIndex == index) {
//            logger.info("COMPUTTTEE:: " +  curve.multiply(CommonConfiguration.g, sharingState.getShare1().getY()));
//            logger.info("PROOOOOOOF:: " +   proof.getA0());
//        }
//
//        final BigInteger x = BigInteger.valueOf(senderIndex);
//        final EcPoint shareCommitment = PublicSharingGenerator.interpolatePedersonCommitments(x,
//                sharingState.getPedersenCommitments());
//        if (ZeroKnowledgeProver.verifyProof(shareCommitment, proof) && senderIndex != index) {
//            sharingState.getVerifications().put(senderIndex, proof.getA0());
//        }

//        logger.info("xxxx " + sharingState.getVerifications());

        // Ignore this proof, we've already received enough
        if (sharingState.getQualifiedProofs().size() < this.k) {

            // Interpolate pedersen commitments to the location of this shareholder
            final BigInteger x = BigInteger.valueOf(senderIndex);
            final EcPoint shareCommitment = PublicSharingGenerator.interpolatePedersonCommitments(x,
                    sharingState.getPedersenCommitments());

            // Verify proof
            if (ZeroKnowledgeProver.verifyProof(shareCommitment, proof)) {

                // Add G^s_i to the set of qualified public keys
                sharingState.getQualifiedProofs().put(senderIndex, proof.getA0()); // Add g^si indexed by i

            } else {
                throw new InvalidZeroKnowledgeProofException("Shareholder " + senderIndex + " send an invalid proof");
            }

            // If size of qualified proofs == k, then interpolate the rest, including for
            // the public key
            if (sharingState.getQualifiedProofs().size() == this.k) {
                logger.info("PerfMeas:EciesRefreshCommunicationTwo:" + (System.nanoTime()-this.getStartCommunication()));

                interpolatePublicKeys(senderEpoch);

                if (senderEpoch > this.getCurrentEpoch()) {
                    final long newEpoch = currentEpoch.incrementAndGet();
                    logger.info("Refresh complete for secret '" + ApvssShareholder.this.secretName
                            + "', now at epoch: " + newEpoch);
                }
            }
        }
    }

    /**
     * Determine the overall Public Key associated with the distributed secret "x",
     * where y = g^x This is done by interpolating each of the values y_i = g^x_i,
     * and then summing the g^x_i for all i in Qual
     */
    private synchronized void interpolatePublicKeys(final long senderEpoch) {
        logger.info("interpolatePublicKeys");
        long start, end;
        start = System.nanoTime();

        // Get sharing state for the current epoch
        final SharingState sharingState = getSharing(senderEpoch);

        // Use interpolation of the K published values to recover the public keys
        final List<DerivationResult> provenShareKeys = new ArrayList<>();

        for (final Entry<Integer, EcPoint> entry : sharingState.getQualifiedProofs().entrySet()) {
            final Integer i = entry.getKey();
            final EcPoint sharePublicKey = entry.getValue();
            final DerivationResult result = new DerivationResult(BigInteger.valueOf(i), sharePublicKey);
            provenShareKeys.add(result);
        }

        final List<DerivationResult> shareVerificationKeys = new ArrayList<>();
        for (int i = 0; i <= this.n; i++) {
            sharingState.getSharePublicKeys()[i] = Polynomials.interpolateExponents(provenShareKeys, this.k, i);
            shareVerificationKeys
                    .add(new DerivationResult(BigInteger.valueOf(i), sharingState.getSharePublicKeys()[i]));
        }

        // Convert the share public keys to Feldman Coefficients using matrix inversion
        sharingState.setFeldmanValues(Polynomials.interpolateCoefficientsExponents(shareVerificationKeys, this.k));

        end = System.nanoTime();
        logger.info("PerfMeas:EciesInterpolatePublicEnd:" + (end - start));

        final long startTime = sharingState.getStartTime();
        final long endVerification = System.nanoTime();
        logger.info("PerfMeas:EciesRefreshTotalEnd:" + (endVerification - startTime));
//        logger.info("Time to establish verification keys: "
//                + (((double) (endVerification - startTime)) / 1_000_000_000.0) + " seconds");

        // Print our share
        logger.info("Sharing Result:");
        logger.info("This Server's Share:     s_" + this.index + "     =  " + sharingState.getShare1());

        // Print secret verification key
        logger.info("Secret Verification key: g^{s}   =  " + sharingState.getSharePublicKeys()[0]);
//        logger.info("---------------------------------------------------------------------------------------------------------------------------------------");
//        logger.info("Secret Verification key: g^{s_i}   =  " + curve.multiply(CommonConfiguration.g, sharingState.getShare1().getY()));


        // Print share verification keys
        for (int i = 1; i <= n; i++) {
            logger.info("Share Verification key:  g^{s_" + i + "} =  " + sharingState.getSharePublicKeys()[i]);
        }

        // Print Feldman Coefficients
        for (int i = 0; i < k; i++) {
            logger.info("Feldman Coefficient:     g^{a_" + i + "} =  " + sharingState.getFeldmanValues()[i]);
        }

        sharingState.setCreationTime(new Date());

        if (senderEpoch == 0) {
            logger.info("DKG Complete!");
        } else {
            logger.info("Refresh Complete!");

            // Sanity check, make sure public keys match before advancing epoch state
            if (this.getCurrentSharing().getSharePublicKeys()[0].equals(sharingState.getSharePublicKeys()[0])) {
                logger.info(" Consistency with previous epoch has been verified.");

                // Delete the previous share
                this.getCurrentSharing().setShare1(null);

            } else {
                throw new RuntimeException("Our new sharing is inconsistent with the previous epoch.");
            }

        }

        // Schedule Proactive Refresh Task
        logger.info("Scheduling next Refresh to occur in " + this.getRefreshFrequency() + " seconds");
        final int refreshPeriodMillis = this.getRefreshFrequency() * 1000;
        this.timer.schedule(new RefreshTask(), refreshPeriodMillis);

        // logger.info("Signatures generated: " + SigningUtil.signCount.get());
        // logger.info("Signatures verified: " + SigningUtil.verCount.get());
    }

    public SimpleEntry<BigInteger, BigInteger> computeEncryptedPartial(final int requesterIndex) {

        // Get sharing state for the current epoch
        final SharingState sharingState = getCurrentSharing();

        // TODO: Include this in the response
        final long partialEpoch = sharingState.getEpochNumber();

        // K is the index of the share to compute a partial for
        final BigInteger k = BigInteger.valueOf(requesterIndex);

        // Determine list of contributors
        final List<Integer> contributors = new ArrayList<>(sharingState.getQualifiedSharings().keySet());
        Collections.sort(contributors);
        final BigInteger[] xCoords = contributors.stream().map(i -> BigInteger.valueOf(i)).toArray(BigInteger[]::new);

        // Use our decryption key to access our shares
        final PaillierPrivateKey decryptionKey = (PaillierPrivateKey) this.keyLoader.getDecryptionKey();

        // Use the sub sharings from the current epoch to produce the partial
        BigInteger share1Part = BigInteger.ZERO;
        BigInteger share2Part = BigInteger.ZERO;
        for (final BigInteger j : xCoords) {

            // j is the index of the shareholder who provided us with our share
            final PublicSharing subSharing = sharingState.getQualifiedSharings().get(j.intValue());

            // Decrypt our shares
            final ShamirShare share1j = subSharing.accessShare1(index - 1, decryptionKey);
            final ShamirShare share2j = subSharing.accessShare2(index - 1, decryptionKey);

            // Compute Lagrange co-efficient
            final BigInteger L_kj = Polynomials.interpolatePartial(xCoords, k, j, curve.getR());

            // Compute sum
            share1Part = share1Part.add(share1j.getY().multiply(L_kj));
            share2Part = share2Part.add(share2j.getY().multiply(L_kj));
        }
        share1Part = share1Part.mod(curve.getR());
        share2Part = share2Part.mod(curve.getR());

        // Encrypt the partial with recipient's public key
        final PaillierPublicKey encryptionKey = (PaillierPublicKey) this.keyLoader.getEncryptionKey(requesterIndex);
        final BigInteger encryptedShare1Part = PaillierCipher.encrypt(encryptionKey, share1Part);
        final BigInteger encryptedShare2Part = PaillierCipher.encrypt(encryptionKey, share2Part);

        return new SimpleEntry<BigInteger, BigInteger>(encryptedShare1Part, encryptedShare2Part);
    }

    public void recoverShare(final SharingState sharingState,
                             final ConcurrentHashMap<Long, SimpleEntry<BigInteger, BigInteger>> verifiedResults) {

        // FIXME: This reconstructs the previous (n-1) epoch version of the share!
        // FIXME: Add verification of each received result

        // Determine list of contributors
        final List<Long> contributors = new ArrayList<>(verifiedResults.keySet());
        Collections.sort(contributors);
        final BigInteger[] xCoords = contributors.stream().map(i -> BigInteger.valueOf(i)).toArray(BigInteger[]::new);

        logger.error(Arrays.toString(xCoords));

        // Start counters at zero
        BigInteger share1Y = BigInteger.ZERO;
        BigInteger share2Y = BigInteger.ZERO;
        //EcPoint[] combinedPedersenCommitments = new EcPoint[this.k];
        //for (int i = 0; i < this.k; i++) {
        //	combinedPedersenCommitments[i] = EcPoint.pointAtInfinity;
        //}

        // Iterate over every public sharing in qual
        for (final Long contributor : contributors) {

            final BigInteger j = BigInteger.valueOf(contributor);
            //final PublicSharing sharing = sharingState.getQualifiedSharings().get(contributor);

            // Decrypt our shares
            final BigInteger share1 = verifiedResults.get(contributor).getKey();
            final BigInteger share2 = verifiedResults.get(contributor).getValue();

            // Get the commitments
            //final EcPoint[] commitments = sharing.getPedersenCommitments();

            // Compute lagrange co-efficient
            final BigInteger l = Polynomials.interpolatePartial(xCoords, BigInteger.ZERO, j, curve.getR());

            // Add the shares to our running sum
            share1Y = share1Y.add(share1.multiply(l)).mod(curve.getR());
            share2Y = share2Y.add(share2.multiply(l)).mod(curve.getR());

            // Add Pedersen commitments to our running sum
            //for (int i = 0; i < this.k; i++) {
            //	final EcPoint interpolatedCommitment = curve.multiply(commitments[i], l);
            //	combinedPedersenCommitments[i] = curve.addPoints(combinedPedersenCommitments[i],
            //			interpolatedCommitment);
            //}
        }

        // Verify we have the correct share (by comparing against public key
        final EcPoint sharePublicKey1 = curve.multiply(g, share1Y);

//        logger.info("Share1: " + share1Y);
//        logger.info("Share2: " + share2Y);

        if (!sharePublicKey1.equals(sharingState.getSharePublicKeys()[this.index])) {
            logger.error(sharePublicKey1);
            throw new IllegalArgumentException("Failed to recover same public key");
        }

        final EcPoint sharePublicKey2 = curve.multiply(h, share2Y);
        final EcPoint recoveredCommitment = curve.addPoints(sharePublicKey1, sharePublicKey2);

        final EcPoint previousCommitment = PublicSharingGenerator.interpolatePedersonCommitments(
                BigInteger.valueOf(this.index), sharingState.getPedersenCommitments());

        if (!recoveredCommitment.equals(previousCommitment)) {
            throw new IllegalArgumentException("Failed to recover same commitment");
        }

        // We have our shares
        sharingState.setShare1(new ShamirShare(BigInteger.valueOf(this.index), share1Y));
        sharingState.setShare2(new ShamirShare(BigInteger.valueOf(this.index), share2Y));
    }

    /**
     * Returns the unique index of this shareholder
     *
     * @return
     */
    public int getIndex() {
        return this.index;
    }

    /**
     * Returns the public key of the secret: y = g^x
     * <p>
     * This method will return null if called before completion of the DKG protocol
     *
     * @return
     * @see waitForPublicKeys()
     */
    public EcPoint getSecretPublicKey() {
        return getSharePublicKey(0);
    }

    /**
     * Returns the public key of the share for this shareholder: y_i = g^x_i
     * <p>
     * This method will return null if called before DKG protocol has built the
     * public keys
     *
     * @return
     * @see waitForQual();
     */
    public EcPoint getSharePublicKey() {
        return getSharePublicKey(this.index);
    }

    public EcPoint getSharePublicKey(final int index) {
        return getCurrentSharing().getSharePublicKeys()[index];
    }

    public EcPoint getFeldmanValues(final int index) {
        return getCurrentSharing().getFeldmanValues()[index];
    }

    public int getN() {
        return this.n;
    }

    public int getK() {
        return this.k;
    }

    /**
     * Return the set of shareholders who have contributed to the secret x
     * <p>
     * (Only used in tests)
     *
     * @return
     */
    protected SortedSet<Integer> getQualSet() {
        return new TreeSet<>(getCurrentSharing().getQualifiedSharings().keySet());
    }

    /**
     * Return the secret share of this shareholder for g^s
     * <p>
     * (Only used in tests)
     *
     * @return
     */
    public ShamirShare getShare1() {
        return getCurrentSharing().getShare1();
    }

    /**
     * Return the secret share of this shareholder for h^s
     * <p>
     * (Only used in tests)
     *
     * @return
     */
    public ShamirShare getShare2() {
        return getCurrentSharing().getShare2();
    }

    /**
     * Wait until this shareholder has established the set of qualified shareholders
     */
    public void waitForQual() {

        // Get sharing state for the current epoch
        final SharingState sharingState = getCurrentSharing();

        while (sharingState.isQualSetDefined() == false) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                // Ignored
            }
        }
    }

    /**
     * Wait until this shareholder has constructed the public key: y = g^x
     */
    public void waitForPublicKeys() {

        // Get sharing state for the current epoch
        final SharingState sharingState = getCurrentSharing();

        while (sharingState.getSharePublicKeys()[0] == null) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                // Ignored
            }
        }
    }

    public Date getCreationTime() {
        // Creation time of the secret is when the 0th epoch completed
        return this.sharingStates.get(new Long(0)).getCreationTime();
    }

    public long getEpoch() {
        return getCurrentSharing().getEpochNumber();
    }

    public Date getLastRefreshTime() {
        return getCurrentSharing().getCreationTime();
    }

    public int getRefreshFrequency() {
        return refreshFrequency;
    }

    public SharingType getSharingType() {
        return this.sharingType;
    }

    public boolean isEnabled() {
        return this.enabled.get();
    }

    public void setEnabled(boolean isEnabled) {
        this.enabled.set(isEnabled);
    }

    public BigInteger getStoredShareOfSecret() {
        return storedShareOfSecret;
    }

    public void setStoredShareOfSecret(BigInteger storedShareOfSecret) {
        this.storedShareOfSecret = storedShareOfSecret;
    }

    public void deleteShare() {
        getCurrentSharing().setShare1(null);
    }

    public void setRsaSecret(BigInteger shareValue, final RsaSharing rsaSharing) {
        this.sharingType = SharingType.RSA_STORED;
        SharingState state = this.getCurrentSharing();
        state.setCreationTime(new Date());
        state.setShare1(new ShamirShare(BigInteger.valueOf(index), shareValue));
        state.setRsaSharing(rsaSharing);
        state.getSharePublicKeys()[0] = new EcPoint(rsaSharing.getPublicKey().getPublicExponent(), rsaSharing.getPublicKey().getModulus()); // Using EcPoints is a hack
        //for (int i = 0; i < this.n; i++ ) {
        //	state.getSharePublicKeys()[0] = new EcPoint(BigInteger.valueOf(i+1), rsaSharing.getVerificationKeys()[i]); // Using EcPoints is a hack
        //}
    }

    public void setProactiveRsaSecret(RsaProactiveSharing rsaSharing) {
        this.sharingType = SharingType.RSA_PROACTIVE_STORED;
        SharingState state = this.getCurrentSharing();
        state.setCreationTime(new Date());
        this.rsaProactiveSharing = rsaSharing;
//		state.setShare1(new ShamirShare(BigInteger.valueOf(index), shareValue));
//		state.setRsaSharing(rsaSharing);
//		state.getSharePublicKeys()[0] = new EcPoint(rsaSharing.getPublicKey().getPublicExponent(), rsaSharing.getPublicKey().getModulus()); // Using EcPoints is a hack
        //for (int i = 0; i < this.n; i++ ) {
        //	state.getSharePublicKeys()[0] = new EcPoint(BigInteger.valueOf(i+1), rsaSharing.getVerificationKeys()[i]); // Using EcPoints is a hack
        //}
    }

    public ProactiveRsaShareholder getProactiveRsaShareholder() {
        return proactiveRsaShareholder;
    }

    public void setProactiveRsaShareholder(ProactiveRsaShareholder proactiveRsaShareholder) {
        this.sharingType = SharingType.RSA_PROACTIVE_STORED;
        SharingState state = this.getCurrentSharing();
        state.setCreationTime(new Date());
        this.proactiveRsaShareholder = proactiveRsaShareholder;
//        logger.info( this.proactiveRsaShareholder.getProactiveRsaPublicParameters().getG());
//		state.setShare1(new ShamirShare(BigInteger.valueOf(index), shareValue));
//		state.setRsaSharing(rsaSharing);
//		state.getSharePublicKeys()[0] = new EcPoint(rsaSharing.getPublicKey().getPublicExponent(), rsaSharing.getPublicKey().getModulus()); // Using EcPoints is a hack
        //for (int i = 0; i < this.n; i++ ) {
        //	state.getSharePublicKeys()[0] = new EcPoint(BigInteger.valueOf(i+1), rsaSharing.getVerificationKeys()[i]); // Using EcPoints is a hack
        //}
    }

    public void setKyberShareholder(KyberShareholder kyberShareholder) {
        this.sharingType = SharingType.KYBER_STORED;
        SharingState state = this.getCurrentSharing();
        state.setCreationTime(new Date());
        this.kyberShareholder = kyberShareholder;
    }

    public KyberShareholder getKyberShareholder() {
        return this.kyberShareholder;
    }

    public RsaSharing getRsaSharing() {
        return this.getCurrentSharing().getRsaSharing();
    }

    public RsaProactiveSharing getRsaProactiveSharing() {
        return rsaProactiveSharing;
    }

    public enum SharingType {
        PEDERSEN_DKG, FELDMAN_DKG, STORED, RSA_STORED, RSA_PROACTIVE_STORED, KYBER_STORED;
    }

    // Periodic task for stubborn message delivery
    public class RefreshTask extends TimerTask {
        @Override
        public void run() {
            final long currentEpoch = ApvssShareholder.this.nextEpoch.get();
            final long nextEpoch = ApvssShareholder.this.nextEpoch.incrementAndGet();
            logger.info("Performing Refresh for secret '" + ApvssShareholder.this.secretName + "' epoch: ("
                    + currentEpoch + " -> " + nextEpoch + ")");
            if (ApvssShareholder.this.getSharingType().equals(SharingType.RSA_PROACTIVE_STORED))
                refreshRsaSharing(nextEpoch);
            else
                broadcastPublicSharing(nextEpoch);
        }
    }

    // TODO: Catch all instances of casting (check instance of) or catch
    // ClassCastException


    public long getStartCommunication() {
        return startCommunication;
    }

    public ApvssShareholder setStartCommunication(long startCommunication) {
        this.startCommunication = startCommunication;
        return this;
    }
}