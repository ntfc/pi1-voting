/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package src.org.evoting.schemes;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import org.cssi.paillier.cipher.PaillierException;
import org.evoting.exception.NumberOfVotesException;
import org.evoting.exception.VotingSchemeException;
import org.utils.DataStreamUtils;

/**
 *
 * @author nc
 */
public class OneOutOfLVoting extends Voting {

  public static final int CODE = 0x52;
  private int base;

  /**
   * Only used by the voter Default base is 10
   */
  public OneOutOfLVoting() throws VotingSchemeException {
    this(new ArrayList<String>(), -1, 10);
  }

  /**
   * Create a 1-out-of-L voting <p> L is the number of candidates, or the size
   * of the list of candidates
   *
   * @param cands
   * @param voters
   * @param base
   */
  public OneOutOfLVoting(List<String> cands, int voters, int base) throws
          VotingSchemeException {
    super(voters, cands);
    this.base = base;
    // TODO: create more exceptions (OneOutOfLException, etc)
    if (base <= voters) {
      throw new VotingSchemeException("Base must be greater than number of voters. "
              + "Found base = " + base + " and nVoters = " + voters);
    }

  }

  public int getL() {
    return candidateNames.size();
  }

  public int getBase() {
    return base;
  }

  @Override
  public int getCode() {
    return CODE;
  }

  /**
   * In a 1-out-of-L, the only common property is the base
   *
   * @param dsu
   * @throws IOException
   */
  @Override
  public void sendVotingProperties(DataStreamUtils dsu) throws IOException {
    // send base number
    dsu.writeInt(base);
  }

  /**
   * Assign the base number <p> This method is used only by the voters
   *
   * @param dsu
   * @throws IOException
   */
  @Override
  public void readVotingProperties(DataStreamUtils dsu) throws IOException {
    // read base
    this.base = dsu.readInt();
  }

  /**
   *
   * @param key
   * @param votes
   * @throws NumberOfVotesException
   * @throws VotingSchemeException
   * @throws InvalidKeyException
   * @throws IOException
   */
  @Override
  public Ballot createBallot(PublicKey key, int... votes) throws
          NumberOfVotesException,
          VotingSchemeException, InvalidKeyException, IOException, PaillierException {
    if(getCipher() == null) { // No cipher associated with voting
      throw new VotingSchemeException("No encryption algorithm associated with voting scheme");
    }
    if (votes.length > 1) {
      throw new NumberOfVotesException(
              "Maximum number of votes allowed in 1-out-of-L is one.");
    }
    Ballot ballot = new Ballot();
    BigInteger vote = BigInteger.ZERO; // assumed blank vote as default vote

    if(votes.length > 0 && votes[0] > 0) { // non blank vote
      votes[0]--; // vote option must be in [0..L-1]
      // vote = b^voteOption
      vote = new BigInteger(Integer.toString(base)).pow(votes[0]);
      // encrypt vote
      BigInteger voteEnc = getCipher().enc(key, vote, new SecureRandom());
      ballot.addVote(voteEnc);
    }
    
    return ballot;
    
  }

  /**
   * TODO: finish this method
   *
   * @param key
   * @param tally
   * @return
   * @throws PaillierException
   * @throws InvalidKeyException
   */
  @Override
  public int winner(PrivateKey key, BigInteger tally) throws PaillierException,
          InvalidKeyException {
    throw new UnsupportedOperationException("Not supported yet.");
  }

  /**
   * Creates a String with how many votes each candidate had <p> How does it
   * work? <b>1.</b> the length of tally.toString() must be equal to
   * nrCandidates<br> <b>1. a)</b> if it's not, it adds the necessary zeros to
   * the left of the string. <b>2.</b> the number of blank votes are calculated
   * in the end, by doing votes.size() - nonBlankVotes <b>3.</b> The number of
   * votes in candidate x_(nrCandidates-1) is in the first position of the
   * string, and so on..
   *
   * @param tallyDec
   * @return
   */

  public String votingResults(BigInteger tallyDec, int base) {
    StringBuilder s = new StringBuilder();

    // if needed, adds zeros on the left to tallyDec string
    
    int nonBlankVotes = 0;
    String s1 = tallyDec.toString(base);
    int j;
    int i=0;
    for(j=2;j>=0;j--){
        if(j<=(s1.length()-1)){
            char c = s1.charAt(j);
            System.out.println(c);
            int nrVotes = Integer.parseInt(Character.toString(c),base); 
            nonBlankVotes += nrVotes;
            s.append(super.candidateNames.get(i)).append(" : ").append(nrVotes).
              append("\n");
        }  
        else{
            int nrVotes = 0; 
            s.append(super.candidateNames.get(i)).append(" : ").append(nrVotes).append("\n");
        }
        i++;
    }
    
   /* String result = String.format("%0" + (nrCandidates) + "d", s1);
    System.out.println("result "+result);
    
    char[] number = new char[3];
    int j;
    for(j=0;j<3;j++){
        number[j] = '0';
    }
    for(j=s1.length();j>=0;j--){
        number[j] = s1.charAt(j);
    }
       
    s.append("Resultados:\n");
    System.out.println("Taly dec: " + tallyDec);
    int nonBlankVotes = 0;

    for (int i = (nrCandidates - 1), index = 1; i >= 0; i--, index++) {
      char c = result.charAt(i); // http://stackoverflow.com/q/4221225
      String s2 = Integer.toString(c,10);
      int nVotes = Integer.parseInt(s2);
      nonBlankVotes += nVotes; // add votes in candidate to the total non blank votes
      s.append(super.candidateNames.get(index - 1)).append(" : ").append(nVotes).
              append("\n");
    }*/
    
    int blank = votes.size() - nonBlankVotes;
    s.append("TOTAL: ");
    s.append(nonBlankVotes).append(" votos + ").append(blank).append(
            " em branco\n");
    return s.toString();
  }
}
