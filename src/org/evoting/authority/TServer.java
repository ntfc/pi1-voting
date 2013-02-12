/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.authority;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.evoting.exception.VariableNotSetException;
import org.evoting.schemes.Ballot;
import org.evoting.schemes.Voting;
import org.evoting.schemes.proofs.InteractiveProof;
import org.evoting.schemes.proofs.NonInteractiveProof;
import org.evoting.zkp.ZKPValidMVerifierInt;
import org.evoting.zkp.ZKPValidMVerifierNonInt;
import org.evoting.zkp.ZKPVotedKVerifier;
import org.utils.ByteUtils;
import org.utils.DataStreamUtils;

/**
 *
 * @author nc
 */
public class TServer extends Thread {

  private static final Logger log = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
  private Socket client;
  private PublicKey pubKey;
  private PrivateKey privKey;
  private Voting voting;

  /**
   * Create a thread for each connected voter
   *
   * @param s
   * @param kP
   * @param vot
   */
  public TServer(Socket s, KeyPair kP, Voting vot) {
    this.client = s;
    this.pubKey = kP.getPublic();
    this.privKey = kP.getPrivate();
    this.voting = vot;
  }

  public void receiveBallotNonInteractive(DataStreamUtils dsu) throws
    IOException {
    //zkp boolean verifier
    boolean zkpVerifierSetMessages = true;

    // receive ballot and zkp
    Ballot ballot = new Ballot(voting.getL(), voting.getK());
    for (int i = 0; i < ballot.size(); i++) {
      BigInteger C = dsu.readBigInteger();

      // zkp
      ZKPValidMVerifierNonInt niZKP = new ZKPValidMVerifierNonInt(voting.getS(),
                                                                  (PaillierPublicKey) pubKey);
      // receive proof
      byte[] proofByte = dsu.readBytes();

      //InteractiveProof proof = new InteractiveProof(ByteUtils.byteToArrayByte(proofByte));
      NonInteractiveProof proof = new NonInteractiveProof(ByteUtils.
        byteToArrayByte(proofByte));

      // re-create ballot
      ballot.addVote(i, C, proof);

      // verify
      boolean msgVerif = niZKP.verify(proof, C);
      System.err.println("Verification of C_" + i + " = " + msgVerif);
      zkpVerifierSetMessages = zkpVerifierSetMessages && msgVerif;
    }

    System.err.println("ZKPSetOfMessages: " + zkpVerifierSetMessages);

    //gen VotedKVerifier
    ZKPVotedKVerifier kVerifier = new ZKPVotedKVerifier(pubKey, voting.getK());

    //receive step1
    byte[] step1VotedK = dsu.readBytes();
    kVerifier.receiveStep1(step1VotedK);

    //gen step2
    kVerifier.generateStep2(ballot.getVotes());

    //verifier VotedK
    boolean zkpVerifierVotedK = true;
    try {
      zkpVerifierVotedK = kVerifier.verify();

      System.out.println("ZKPVotedK: " + zkpVerifierVotedK);
    }
    catch (PaillierException | InvalidKeyException ex) {
      log.log(Level.SEVERE, ex.getMessage(), ex);
    }

    // TODO: invalid votes are discarded or not?
    if (zkpVerifierSetMessages && zkpVerifierVotedK) {
      voting.receiveBallot(ballot);
      System.out.println("Valid ballot");
    }
    else {
      voting.addInvalidVote();
      voting.addVoterWhoVoted();
      System.out.println("Invalid ballot");
    }
  }

  public void receiveVotesInteractive(DataStreamUtils dsu) throws IOException,
      VariableNotSetException {
    //zkp boolean verifier
    boolean zkpVerifierSetMessages = true;

    // store votes
    List<BigInteger> votes = new ArrayList<>();
    int ballotSize = voting.getL() + voting.getK();
    for (int i = 0; i < ballotSize; i++) {
      BigInteger C = dsu.readBigInteger();
      // add the vote to votes
      votes.add(C);

      // zkp
      ZKPValidMVerifierInt iZKP = new ZKPValidMVerifierInt(voting.getS(),
                                                           (PaillierPublicKey) pubKey);

      // receive step1
      InteractiveProof step1 = new InteractiveProof(dsu.readBytes());
      iZKP.receiveStep1(step1);
      // send step2
      InteractiveProof step2 = iZKP.generateStep2();
      dsu.writeBytes(step2.getProofEncoded());
      // receive step3
      InteractiveProof step3_1 = new InteractiveProof(dsu.readBytes()); // e
      InteractiveProof step3_2 = new InteractiveProof(dsu.readBytes()); // v
      iZKP.receiveStep3(step3_1, step3_2);


      // verify
      boolean msgVerif = iZKP.verify(C);
      System.err.println("Verification of C_" + i + " = " + msgVerif);
      zkpVerifierSetMessages = zkpVerifierSetMessages && msgVerif;
    }

    System.err.println("ZKPSetOfMessages: " + zkpVerifierSetMessages);

    //gen VotedKVerifier
    ZKPVotedKVerifier kVerifier = new ZKPVotedKVerifier(pubKey, voting.getK());

    //receive step1
    byte[] step1VotedK = dsu.readBytes();
    kVerifier.receiveStep1(step1VotedK);

    //gen step2
    kVerifier.generateStep2(votes);

    //verifier VotedK
    boolean zkpVerifierVotedK = true;
    try {
      zkpVerifierVotedK = kVerifier.verify();

      System.out.println("ZKPVotedK: " + zkpVerifierVotedK);
    }
    catch (PaillierException | InvalidKeyException ex) {
      log.log(Level.SEVERE, ex.getMessage(), ex);
    }

    // TODO: invalid votes are discarded or not?
    if (zkpVerifierSetMessages && zkpVerifierVotedK) {
      voting.receiveVotes(votes);
      System.out.println("Valid ballot");
    }
    else {
      voting.addInvalidVote();
      voting.addVoterWhoVoted();
      System.out.println("Invalid ballot");
    }
  }

  @Override
  public void run() {
    try {
      DataStreamUtils dsu = new DataStreamUtils(client.getInputStream(), client.
        getOutputStream());

      try {
        // send voting properties, like base
        voting.sendVotingProperties(dsu);
        // send voting candidates to the voter
        voting.sendVotingCandidates(dsu);
        // send publickey
        dsu.writeBytes(pubKey.getEncoded());

        // receive votes non interactive
        receiveBallotNonInteractive(dsu);
        // receive votes interactive
        //receiveVotesInteractive(dsu);

      }
      catch (IOException e) {
        log.log(Level.SEVERE, e.getMessage(), e);
      }
      finally {
        dsu.close();
      }
    }
    catch (IOException e) {
      log.log(Level.SEVERE, e.getMessage(), e);
    }
  }
}
