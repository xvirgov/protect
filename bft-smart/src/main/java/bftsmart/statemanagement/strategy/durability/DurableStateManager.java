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
package bftsmart.statemanagement.strategy.durability;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Queue;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.locks.ReentrantLock;

import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.ApplicationState;
import bftsmart.statemanagement.SMMessage;
import bftsmart.statemanagement.strategy.BaseStateManager;
import bftsmart.tom.core.DeliveryThread;
import bftsmart.tom.core.ExecutionManager;
import bftsmart.tom.core.TOMLayer;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.durability.DurabilityCoordinator;

import bftsmart.tom.util.TOMUtil;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DurableStateManager extends BaseStateManager {

	// private LCManager lcManager;
	private ExecutionManager execManager;

	private ReentrantLock lockTimer = new ReentrantLock();
	private Timer stateTimer = null;
	private final static long INIT_TIMEOUT = 40000;
	private long timeout = INIT_TIMEOUT;

	private CSTRequestF1 cstRequest;

	private CSTState stateCkp;
	private CSTState stateLower;
	private CSTState stateUpper;

	private static final Logger logger = LogManager.getLogger(DurableStateManager.class);

	@Override
	public void init(TOMLayer tomLayer, DeliveryThread dt) {
		SVController = tomLayer.controller;

		this.tomLayer = tomLayer;
		this.dt = dt;
		// this.lcManager = tomLayer.getSyncher().getLCManager();
		this.execManager = tomLayer.execManager;

		state = null;
		lastCID = 1;
		waitingCID = -1;

		appStateOnly = false;
	}

	@Override
	protected void requestState() {
		if (tomLayer.requestsTimer != null)
			tomLayer.requestsTimer.clearAll();

		int myProcessId = SVController.getStaticConf().getProcessId();
		int[] otherProcesses = SVController.getCurrentViewOtherAcceptors();
		int globalCkpPeriod = SVController.getStaticConf().getGlobalCheckpointPeriod();

		CSTRequestF1 cst = new CSTRequestF1(waitingCID);
		cst.defineReplicas(otherProcesses, globalCkpPeriod, myProcessId);
		this.cstRequest = cst;
		CSTSMMessage cstMsg = new CSTSMMessage(myProcessId, waitingCID, TOMUtil.SM_REQUEST, cst, null, null, -1, -1);
		tomLayer.getCommunication().send(SVController.getCurrentViewOtherAcceptors(), cstMsg);

		System.out
				.println("(TOMLayer.requestState) I just sent a request to the other replicas for the state up to CID "
						+ waitingCID);

		TimerTask stateTask = new TimerTask() {
			public void run() {
				int[] myself = new int[1];
				myself[0] = SVController.getStaticConf().getProcessId();
				tomLayer.getCommunication().send(myself,
						new CSTSMMessage(-1, waitingCID, TOMUtil.TRIGGER_SM_LOCALLY, null, null, null, -1, -1));
			}
		};

		stateTimer = new Timer("state timer");
		timeout = timeout * 2;
		stateTimer.schedule(stateTask, timeout);
	}

	@Override
	public void stateTimeout() {
		lockTimer.lock();
		logger.debug(
				"(StateManager.stateTimeout) Timeout for the replica that was supposed to send the complete state. Changing desired replica.");
		logger.debug("Timeout no timer do estado!");
		if (stateTimer != null)
			stateTimer.cancel();
		reset();
		requestState();
		lockTimer.unlock();
	}

	@Override
	public void SMRequestDeliver(SMMessage msg, boolean isBFT) {
		logger.debug("(TOMLayer.SMRequestDeliver) invoked method");
		logger.debug("(TOMLayer.SMRequestDeliver) invoked method");
		if (SVController.getStaticConf().isStateTransferEnabled() && dt.getRecoverer() != null) {
			logger.debug("(TOMLayer.SMRequestDeliver) The state transfer protocol is enabled");
			logger.debug("(TOMLayer.SMRequestDeliver) I received a state request for CID " + msg.getCID()
					+ " from replica " + msg.getSender());
			CSTSMMessage cstMsg = (CSTSMMessage) msg;
			CSTRequestF1 cstConfig = cstMsg.getCstConfig();
			boolean sendState = cstConfig.getCheckpointReplica() == SVController.getStaticConf().getProcessId();
			if (sendState)
				logger.debug("(TOMLayer.SMRequestDeliver) I should be the one sending the state");

			logger.debug("--- state asked");

			int[] targets = { msg.getSender() };
			InetSocketAddress address = SVController.getCurrentView()
					.getAddress(SVController.getStaticConf().getProcessId());
			String myIp = address.getHostName();
			int myId = SVController.getStaticConf().getProcessId();
			int port = 4444 + myId;
			address = new InetSocketAddress(myIp, port);
			cstConfig.setAddress(address);
			CSTSMMessage reply = new CSTSMMessage(myId, msg.getCID(), TOMUtil.SM_REPLY, cstConfig, null,
					SVController.getCurrentView(), tomLayer.getSynchronizer().getLCManager().getLastReg(),
					tomLayer.execManager.getCurrentLeader());

			StateSenderServer stateServer = new StateSenderServer(port);
			stateServer.setRecoverable(dt.getRecoverer());
			stateServer.setRequest(cstConfig);
			new Thread(stateServer).start();

			tomLayer.getCommunication().send(targets, reply);

		}
	}

	@Override
	public void SMReplyDeliver(SMMessage msg, boolean isBFT) {
		lockTimer.lock();
		CSTSMMessage reply = (CSTSMMessage) msg;
		if (SVController.getStaticConf().isStateTransferEnabled()) {
			logger.debug("(TOMLayer.SMReplyDeliver) The state transfer protocol is enabled");
			logger.debug("(TOMLayer.SMReplyDeliver) I received a state reply for CID " + reply.getCID()
					+ " from replica " + reply.getSender());

			logger.debug("--- Received CID: " + reply.getCID() + ". Waiting " + waitingCID);
			if (waitingCID != -1 && reply.getCID() == waitingCID) {

				int currentRegency = -1;
				int currentLeader = -1;
				View currentView = null;
				// CertifiedDecision currentProof = null;

				if (!appStateOnly) {
					senderRegencies.put(reply.getSender(), reply.getRegency());
					senderLeaders.put(reply.getSender(), reply.getLeader());
					senderViews.put(reply.getSender(), reply.getView());
					// senderProofs.put(msg.getSender(),
					// msg.getState().getCertifiedDecision(SVController));
					if (enoughRegencies(reply.getRegency()))
						currentRegency = reply.getRegency();
					if (enoughLeaders(reply.getLeader()))
						currentLeader = reply.getLeader();
					if (enoughViews(reply.getView())) {
						currentView = reply.getView();
						if (!currentView.isMember(SVController.getStaticConf().getProcessId())) {
							logger.debug("Not a member!");
						}
					}
					// if (enoughProofs(waitingCID, this.tomLayer.getSynchronizer().getLCManager()))
					// currentProof = msg.getState().getCertifiedDecision(SVController);

				} else {
					currentLeader = tomLayer.execManager.getCurrentLeader();
					currentRegency = tomLayer.getSynchronizer().getLCManager().getLastReg();
					currentView = SVController.getCurrentView();
				}

				logger.debug("(TOMLayer.SMReplyDeliver) The reply is for the CID that I want!");

				InetSocketAddress address = reply.getCstConfig().getAddress();
				Socket clientSocket;
				ApplicationState stateReceived = null;
				try {
					clientSocket = new Socket(address.getHostName(), address.getPort());
					ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
					stateReceived = (ApplicationState) in.readObject();
				} catch (UnknownHostException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				if (stateReceived instanceof CSTState) {
					senderStates.put(reply.getSender(), stateReceived);
					if (reply.getSender() == cstRequest.getCheckpointReplica())
						this.stateCkp = (CSTState) stateReceived;
					if (reply.getSender() == cstRequest.getLogLower())
						this.stateLower = (CSTState) stateReceived;
					if (reply.getSender() == cstRequest.getLogUpper())
						this.stateUpper = (CSTState) stateReceived;
				}

				if (senderStates.size() == 3) {

					CommandsInfo[] lowerLog = stateLower.getLogLower();
					CommandsInfo[] upperLog = stateUpper.getLogUpper();
					logger.debug("lowerLog ");
					if (lowerLog != null)
						logger.debug(lowerLog.length);
					logger.debug("upperLog ");
					if (upperLog != null)
						logger.debug(upperLog.length);

					boolean haveState = false;
					byte[] lowerbytes = TOMUtil.getBytes(lowerLog);
					logger.debug("Log lower bytes size: " + lowerbytes.length);
					byte[] upperbytes = TOMUtil.getBytes(upperLog);
					logger.debug("Log upper bytes size: " + upperbytes.length);

					byte[] lowerLogHash = TOMUtil.computeHash(lowerbytes);
					byte[] upperLogHash = TOMUtil.computeHash(upperbytes);

					// validate lower log
					if (Arrays.equals(stateCkp.getHashLogLower(), lowerLogHash))
						haveState = true;
					else
						logger.debug("Lower log don't match");
					// validate upper log
					if (!haveState || !Arrays.equals(stateCkp.getHashLogUpper(), upperLogHash)) {
						haveState = false;
						logger.debug("Upper log don't match");
					}

					CSTState statePlusLower = new CSTState(stateCkp.getSerializedState(),
							TOMUtil.getBytes(stateCkp.getSerializedState()), stateLower.getLogLower(),
							stateCkp.getHashLogLower(), null, null, stateCkp.getCheckpointCID(),
							stateUpper.getCheckpointCID(), SVController.getStaticConf().getProcessId());

					if (haveState) { // validate checkpoint
						logger.debug("validating checkpoint!!!");
						dt.getRecoverer().setState(statePlusLower);
						byte[] currentStateHash = ((DurabilityCoordinator) dt.getRecoverer()).getCurrentStateHash();
						if (!Arrays.equals(currentStateHash, stateUpper.getHashCheckpoint())) {
							logger.debug("ckp hash don't match");
							haveState = false;
						}
					}

					logger.debug("-- current regency: " + currentRegency);
					logger.debug("-- current leader: " + currentLeader);
					logger.debug("-- current view: " + currentView);
					if (currentRegency > -1 && currentLeader > -1 && currentView != null && haveState
							&& (!isBFT || /* currentProof != null || */ appStateOnly)) {
						logger.debug("---- RECEIVED VALID STATE ----");

						logger.debug("(TOMLayer.SMReplyDeliver) The state of those replies is good!");
						logger.debug("(TOMLayer.SMReplyDeliver) CID State requested: " + reply.getCID());
						logger.debug("(TOMLayer.SMReplyDeliver) CID State received: " + stateUpper.getLastCID());

						tomLayer.getSynchronizer().getLCManager().setLastReg(currentRegency);
						tomLayer.getSynchronizer().getLCManager().setNextReg(currentRegency);
						tomLayer.getSynchronizer().getLCManager().setNewLeader(currentLeader);

						tomLayer.execManager.setNewLeader(currentLeader);

						// if (currentProof != null && !appStateOnly) {
						//
						// logger.debug("Installing proof for consensus " + waitingCID);
						//
						// Consensus cons = execManager.getConsensus(waitingCID);
						// Epoch e = null;
						//
						// for (ConsensusMessage cm : currentProof.getConsMessages()) {
						//
						// e = cons.getEpoch(cm.getEpoch(), true, SVController);
						// if (e.getTimestamp() != cm.getEpoch()) {
						//
						// logger.debug("Strange... proof contains messages from more than just
						// one epoch");
						// e = cons.getEpoch(cm.getEpoch(), true, SVController);
						// }
						// e.addToProof(cm);
						//
						// if (cm.getType() == MessageFactory.ACCEPT) {
						// e.setAccept(cm.getSender(), cm.getValue());
						// }
						//
						// else if (cm.getType() == MessageFactory.WRITE) {
						// e.setWrite(cm.getSender(), cm.getValue());
						// }
						//
						// }
						//
						//
						// if (e != null) {
						//
						// byte[] hash = tomLayer.computeHash(currentProof.getDecision());
						// e.propValueHash = hash;
						// e.propValue = currentProof.getDecision();
						// e.deserializedPropValue =
						// tomLayer.checkProposedValue(currentProof.getDecision(), false);
						// cons.decided(e, false);
						//
						// logger.debug("Successfully installed proof for consensus " +
						// waitingCID);
						//
						// } else {
						// logger.debug("Failed to install proof for consensus " + waitingCID);
						//
						// }
						//
						// }

						// I might have timed out before invoking the state transfer, so
						// stop my re-transmission of STOP messages for all regencies up to the current
						// one
						if (currentRegency > 0)
							tomLayer.getSynchronizer().removeSTOPretransmissions(currentRegency - 1);

						logger.debug("trying to acquire deliverlock");
						dt.deliverLock();
						logger.debug("acquired");

						// this makes the isRetrievingState() evaluates to false
						waitingCID = -1;
						dt.update(stateUpper);

						// Deal with stopped messages that may come from
						// synchronization phase
						if (!appStateOnly && execManager.stopped()) {
							Queue<ConsensusMessage> stoppedMsgs = execManager.getStoppedMsgs();
							for (ConsensusMessage stopped : stoppedMsgs) {
								if (stopped.getNumber() > state.getLastCID())
									execManager.addOutOfContextMessage(stopped);
							}
							execManager.clearStopped();
							execManager.restart();
						}

						logger.debug("Processing out of context messages");
						tomLayer.processOutOfContext();

						if (SVController.getCurrentViewId() != currentView.getId()) {
							logger.debug("Installing current view!");
							SVController.reconfigureTo(currentView);
						}

						isInitializing = false;

						dt.canDeliver();
						dt.deliverUnlock();

						reset();

						logger.debug("I updated the state!");

						tomLayer.requestsTimer.Enabled(true);
						tomLayer.requestsTimer.startTimer();
						if (stateTimer != null)
							stateTimer.cancel();

						if (appStateOnly) {
							appStateOnly = false;
							tomLayer.getSynchronizer().resumeLC();
						}
					} else if (state == null && (SVController.getCurrentViewN() / 2) < getReplies()) {
						logger.debug("---- DIDNT RECEIVE STATE ----");

						logger.debug("(TOMLayer.SMReplyDeliver) I have more than "
								+ (SVController.getCurrentViewN() / 2) + " messages that are no good!");

						waitingCID = -1;
						reset();

						if (stateTimer != null)
							stateTimer.cancel();

						if (appStateOnly) {
							requestState();
						}
					} else if (!haveState) {
						logger.debug("---- RECEIVED INVALID STATE  ----");

						logger.debug(
								"(TOMLayer.SMReplyDeliver) The replica from which I expected the state, sent one which doesn't match the hash of the others, or it never sent it at all");

						reset();
						requestState();

						if (stateTimer != null)
							stateTimer.cancel();
					}
				}
			}
		}
		lockTimer.unlock();
	}

}
