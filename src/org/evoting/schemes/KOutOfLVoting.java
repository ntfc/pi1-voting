/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.schemes;

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
public class KOutOfLVoting extends Voting {
  public static final int CODE = 0x14;
  private int k, l;
  private int base;


  /**
   * Only used by the voter Default K=1, base is 10
   */
  public KOutOfLVoting() throws VotingSchemeException {
    this(1, 10, -1, new ArrayList<String>());
  }
  // L = cands.size()
  public KOutOfLVoting(int K, int base, int voters, List<String> cands) throws VotingSchemeException {
    super(voters, cands);
    this.base = base;
    this.k = K;
    this.l = cands.size();
    if(!isBaseOK()) {
      // base not valid. cannot create voting scheme
      throw new VotingSchemeException("Base must be greater than base. "
              + "Found base = " + base + " and nVoters = " + voters);
    }
  }

  public int getK() {
    return k;
  }

  public int getL() {
    return l;
  }

  public int getBase() {
    return base;
  }

  @Override
  public int getCode() {
    return CODE;
  }

  public int calcMaxM() {
    int i = nrCandidates - k + 1;
    int tot = 0;
    for( ; i <= nrCandidates; i++)
      tot += base^(i-1);
    return tot;
  }

  public int calcMaxT() {
    return nrVoters * calcMaxM();
  }

  public boolean isBaseOK() {
    return base > nrVoters;
  }

  @Override
  public void sendVotingProperties(DataStreamUtils dsu) throws IOException {
    // send base
    dsu.writeInt(base);
    // send k
    dsu.writeInt(k);
    // send l
    dsu.writeInt(l);
  }

  @Override
  public void readVotingProperties(DataStreamUtils dsu) throws IOException {
    // read base
    base = dsu.readInt();
    // read k
    k = dsu.readInt();
    // read l
    l = dsu.readInt();
  }

  @Override
  public Ballot createBallot(PublicKey key, int... votes) throws NumberOfVotesException,
          VotingSchemeException, InvalidKeyException, IOException,
          PaillierException {
    if(getCipher() == null) { // No cipher associated with voting
      throw new VotingSchemeException("No encryption algorithm associated with voting scheme");
    }
    if (votes.length > getK()) {
      throw new NumberOfVotesException(
              "Maximum number of votes allowed in K-out-of-L is K.");
    }
    Ballot ballot = new Ballot();
    BigInteger vote = BigInteger.ZERO; // assumed blank vote as default vote
    if(votes.length > 0 && votes[0] != 0) { // non blank vote
      for(int vv : votes) {
        vv--; // vote option must be in [0..L-1]
        // vote = b^voteOption
        vote = new BigInteger(Integer.toString(base)).pow(vv);
        // add vote to the ballot
        BigInteger voteEnc = getCipher().enc(key, vote, new SecureRandom());
        ballot.addVote(voteEnc);
      }

    }

    return ballot;
  }

  @Override
  public int winner(PrivateKey key, BigInteger tally) throws PaillierException,
          InvalidKeyException {
    throw new UnsupportedOperationException("Not supported yet.");
  }

  // TODO: the winners are the K candidates with the most votes
  @Override
  public String votingResults(BigInteger tallyDec, int b) {
    
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
      
    /*StringBuilder s = new StringBuilder();

    // if needed, adds zeros on the left to tallyDec string
    String result = String.format("%0" + (nrCandidates) + "d", tallyDec);

    s.append("Resultados:\n");

    int nonBlankVotes = 0;

    for (int i = (nrCandidates - 1), index = 1; i >= 0; i--, index++) {
      int nVotes = result.charAt(i) - '0'; // http://stackoverflow.com/q/4221225
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
