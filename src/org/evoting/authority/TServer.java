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
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.evoting.exception.VariableNotSetException;
import org.evoting.schemes.Ballot;
import org.evoting.schemes.Voting;
import org.evoting.zkp.Proof;
import org.evoting.zkp.interactive.ZKPSetOfMessagesVerifier;
import org.evoting.zkp.interactive.ZKPVotedKVerifier;
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
        
        //zkp boolean verifier
        boolean zkpVerifierSetMessages = true;
        
        // receive ballot and zkp
        Ballot ballot = new Ballot(voting.getL(), voting.getK());
        for(int i = 0; i < ballot.size(); i++) {
          BigInteger C = dsu.readBigInteger();
          ballot.addVote(i, C);
          

          // zkp
          ZKPSetOfMessagesVerifier zkp = new ZKPSetOfMessagesVerifier(voting.getS(), (PaillierPublicKey)pubKey, C);
          // receive step1
          Proof stp1 = new Proof(dsu.readBytes());
          
          zkp.receiveStep1(stp1);

          // send challenge
          try {
            dsu.writeBytes(zkp.generateStep2().getProofAsByteArray());
            
            // receive step3
            byte[] e = dsu.readBytes();
            byte[] v = dsu.readBytes();
            
            zkp.receiveStep3(e, v);

            // verify
            boolean msgVerif = zkp.verify();
            System.err.println("Verification of C_" + i + " = " + msgVerif);
            zkpVerifierSetMessages = zkpVerifierSetMessages && msgVerif;

          }
          catch(VariableNotSetException ex) {
            System.err.println(ex.getMessage());
          }
        }
        
        System.out.println("ZKPSetOfMessages: " + zkpVerifierSetMessages);
        
        
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
          
          System.out.println("ZKPVotedK: "+ zkpVerifierVotedK);
        } 
        catch (PaillierException |InvalidKeyException ex) {
          log.log(Level.SEVERE, ex.getMessage(), ex);
        }

        // TODO: invalid votes are discarded or not?
        if(zkpVerifierSetMessages && zkpVerifierVotedK){
          voting.receiveBallot(ballot);
          System.err.println("Valid ballot");
        }
        else{
          voting.addInvalidVote();
          System.err.println("Invalid ballot");
        }
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
