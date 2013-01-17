/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package src.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.security.Security;
import org.cssi.provider.CssiProvider;
import src.org.evoting.schemes.Ballot;
import src.org.evoting.schemes.OneOutOfLVoting;
import src.org.evoting.voter.VoterClient;

/**
 *
 * @author nc
 */
public class clienteTest implements Runnable {

    /**
     * @param args the command line arguments
     */
    
    int vote;
    
    public clienteTest(int vote){
        this.vote = vote;
    }
    
    public void run() {
        try {
            Security.addProvider(new CssiProvider());
            VoterClient client = new VoterClient(new Socket("localhost", 4545));
            // receive voting properties from authority like candidate names, base, etc
            client.setUpVoting();

            // print list of candidates
            int i = 1;
            for (String cand : client.getVoting().getCandidateNames()) {
                System.out.println((i++) + ": " + cand);
           }
            //String option;
            //BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            //option = stdIn.readLine();


           // if (option.isEmpty()) {
             //   option = "0";
            //}
            int optionInt = vote; //Integer.valueOf(option);
            //Vote
            //client.vote(optionInt);
            Ballot ballot = client.getVoting().createBallot(client.getPublicKey(), optionInt);
            client.submitBallot(ballot);
            System.out.println("Ballot sent");
        } catch (Exception e) {
        }
    }
}
   

   /* public static void main(String[] args) throws Exception {
    Security.addProvider(new CssiProvider());
    VoterClient client = new VoterClient(new Socket("localhost", 4545));
    // receive voting properties from authority like candidate names, base, etc
    client.setUpVoting();
    
    // print list of candidates
    int i = 1;
    for(String cand : client.getVoting().getCandidateNames()) {
    System.out.println((i++) + ": " + cand);
    }
    String option;
    BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
    option = stdIn.readLine();
    
    
    if(option.isEmpty() ) {
    option = "0";
    }
    Integer optionInt = Integer.valueOf(option);
    //Vote
    //client.vote(optionInt);
    Ballot ballot = client.getVoting().createBallot(client.getPublicKey(), optionInt);
    client.submitBallot(ballot);
    System.out.println("Ballot sent");
    }
    */