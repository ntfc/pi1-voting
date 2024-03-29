/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test;

import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Security;
import org.cssi.provider.CssiProvider;
import org.evoting.schemes.Ballot;
import org.evoting.voter.VoterClient;

/**
 *
 * @author nc
 */
public class clienteTest implements Runnable {

  /**
   * @param args the command line arguments
   */
  int vote1, vote2;
  BigInteger voterID;

  public clienteTest(BigInteger voterId, int vote1, int vote2) {
    Security.addProvider(new CssiProvider());
    this.vote1 = vote1;
    this.vote2 = vote2;
    this.voterID = voterId;
  }

  public void run() {
    try {
      
      VoterClient client = new VoterClient(new Socket("localhost", 4545), voterID);
      // receive voting properties from authority like candidate names, base, etc
      client.setUpVoting();

      // print list of candidates
      int i = 1;
      for (String cand : client.getVoting().getCandidateNames()) {
        System.out.println((i++) + ": " + cand);
      }
      
      /*Ballot ballot;
      if(vote1 != vote2) {
        ballot = client.getVoting().createBallot(client.getPublicKey(),
                                                      vote1, vote2);
        System.out.println("Voted for: " + vote1 + ", " + vote2);
      }
      else {
        ballot = client.getVoting().createBallot(client.getPublicKey(),vote1);
        System.out.println("Voted for: " + vote1);
      }

      
      client.submitBallot(ballot);
      client.submitVoteInterative();*/
      
    }
    catch (Exception e) {
    }
  }

  public static void main(String[] args) throws Exception{
    Security.addProvider(new CssiProvider());
    VoterClient client = new VoterClient(new Socket("localhost", 4545), new BigInteger(5, new SecureRandom()), true);
    // receive voting properties from authority like candidate names, base, etc
    client.setUpVoting();
    client.submitVote(1);
  }
}
