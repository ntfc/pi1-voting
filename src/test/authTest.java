/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.provider.CssiProvider;
import org.evoting.authority.VotingServer;
import org.evoting.schemes.KOutOfLVoting;
import org.evoting.schemes.OneOutOfLVoting;
import org.evoting.schemes.Voting;
import org.evoting.schemes.YesNoVoting;

/**
 *
 * @author nc
 */
public class authTest {

  /**
   * @param args the command line arguments
   */
  public static void main(String[] args) throws Exception {
    Security.addProvider(new CssiProvider());
    // Generate keys
    KeyPairGenerator kGen = KeyPairGenerator.getInstance("Paillier", "CSSI");
    KeyPair kP = kGen.generateKeyPair();
    //Voting votingType = new YesNoVoting(3, "José", "António");
    List<String> cands = new ArrayList<>();
    cands.add("Antonio");
    cands.add("Jose");
    cands.add("Carlos");
    /*cands.add("Zé");
    cands.add("Manuel");
    cands.add("Jesus");
    cands.add("Cristo");
    cands.add("Nuno");
    cands.add("Rafael");
    cands.add("Milton");
    cands.add("Deus");*/

    
    Voting votingType = new OneOutOfLVoting(cands, 3, 10);
    //Voting votingType = new YesNoVoting(5, "Sim", "Não");
    //Voting votingType = new KOutOfLVoting(2, 10, 3, cands);

    VotingServer votingServer = new VotingServer(votingType, kP);

    votingServer.startVoting(10000, 4545);
    BigInteger tally = votingServer.getVoting().tallying(kP.getPrivate());
    //int winner = votingServer.getVoting().winner(kP.getPrivate(), tally);
    System.out.println("Results: " + tally);
    System.out.println("Total votes: " + votingServer.getVoting().totalVotes());

    /*int winner = votingServer.getVoting().winner(kP.getPrivate(), tally);
    System.out.println("Winner: " + winner + " (" + votingServer.getVoting().
            getCandidateNames().get(winner) + ")");*/

    BigInteger tallyDec = new PaillierSimple().dec(kP.getPrivate(), tally);
    System.out.println("Tally dec: " + tallyDec);
//    int base = ((OneOutOfLVoting)votingType).getBase();
//    System.out.println("Tally base " + base + ": " + tallyDec.toString(base));
    System.out.println(votingType.votingResults(tallyDec));
  }
}
