/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.authority;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.evoting.exception.VariableNotSetException;
import org.evoting.schemes.Ballot;
import org.evoting.schemes.Voting;
import org.evoting.zkp.ZKPVerifier;
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
        // first of all, send the voting type, so the voter can create its instance
        int votingType = voting.getCode();
        System.out.println("Voting type: " + votingType);
        
        dsu.writeInt(votingType);
        // send voting properties, like base
        voting.sendVotingProperties(dsu);
        // send voting candidates to the voter
        voting.sendVotingCandidates(dsu);
        // send publickey
        dsu.writeBytes(pubKey.getEncoded());
        
        //zkp boolean verifier
        boolean zkpVerifier = true;
        
        // receive ballot and zkp
        Ballot ballot = new Ballot(voting.getNrCandidates());
        for(int i = 0; i < voting.getNrCandidates(); i++) {
          BigInteger C = dsu.readBigInteger();
          ballot.addVote(i, C);
          // zkp
          BigInteger[] S = new  BigInteger[]{BigInteger.ZERO, BigInteger.ONE};
          ZKPVerifier zkp = new ZKPVerifier(S, (PaillierPublicKey)pubKey, C);
          // receive step1
          zkp.receiveStep1(dsu.readBytes());

          // send challenge
          try {
            dsu.writeBytes(zkp.generateStep2());
            
            // receive step3
            byte[] e = dsu.readBytes();
            byte[] v = dsu.readBytes();
            
            zkp.receiveStep3(new byte[][]{v, e});

            // verify
            boolean ver = zkp.verify();
            System.err.println("Verification of C_" + i + " = " + ver);
            if(ver == false){
              zkpVerifier = false;
            }
          }
          catch(VariableNotSetException ex) {
            System.err.println(ex.getMessage());
          }
        }
        
        if(zkpVerifier == true){
          boolean receivedVote = voting.receiveBallot(ballot);
          System.out.println("Ballot accepted: " + receivedVote);
        }
        else{
          System.out.println("Invalid ballot");
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
