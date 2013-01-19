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
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.paillier.cipher.PaillierException;
import org.evoting.exception.NumberOfVotesException;
import org.evoting.exception.VotingSchemeException;
import org.utils.DataStreamUtils;

/**
 *
 * @author nc
 */
public class KOutOfLVoting extends Voting {
  private static final Logger LOG = Logger.getLogger(KOutOfLVoting.class.getName());
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

  public KOutOfLVoting(int K, int base, int voters, List<String> cands) throws
          VotingSchemeException {
    super(voters, cands);

    this.base = base;
    this.k = K;
    this.l = cands.size();
      // base must be greater than nrVoters
      if (base <= nrVoters) {
        // base not valid. cannot create voting scheme
        throw new VotingSchemeException("Base must be greater than number of voters. "
                + "Found base = " + base + " and nVoters = " + voters);
      }
      // base must be smaller or equal than Character.MAX_RADIX (=36)
      if(base > Character.MAX_RADIX) {
        throw new VotingSchemeException("base " + base + " "
                + "greater than Character.MAX_RADIX = " + Character.MAX_RADIX);
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
    for (; i <= nrCandidates; i++) {
      tot += base ^ (i - 1);
    }
    return tot;
  }

  public int calcMaxT() {
    return nrVoters * calcMaxM();
  }

  // n >= Tmax + 1
  public boolean isModuloNOK(BigInteger n) {
    BigInteger tMaxPlusOne = new BigInteger(Integer.toString(calcMaxT() + 1));
    return n.compareTo(tMaxPlusOne) >= 0;
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
  public Ballot createBallot(PublicKey key, int... votes) throws
          NumberOfVotesException,
          VotingSchemeException, InvalidKeyException, IOException,
          PaillierException {
    if (getCipher() == null) { // No cipher associated with voting
      throw new VotingSchemeException(
              "No encryption algorithm associated with voting scheme");
    }
    if (votes.length > getK()) {
      throw new NumberOfVotesException(
              "Maximum number of votes allowed in K-out-of-L is K.");
    }
    Ballot ballot = new Ballot();
    BigInteger vote = BigInteger.ZERO; // assumed blank vote as default vote
    if (votes.length > 0 && votes[0] != 0) { // non blank vote
      for (int vv : votes) {
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
  public String votingResults(BigInteger tallyDec) {
    StringBuilder s = new StringBuilder("Results\n");
    LOG.log(Level.INFO, "tallyDec = {0}", tallyDec.toString());
    // convert tallyDec from base 10 to base defined in the voting scheme
    String tallyBase = tallyDec.toString(base);
    LOG.log(Level.INFO, "tally base {0} = {1}", new Object[]{base, tallyBase});

    // add zeros
    String tallyBaseStr = paddingZeros(tallyBase, getL());

    // count non blank votes
    int nonBlank = 0;
    for (int j = (getL() - 1), index = 0; j >= 0; j--, index++) {
      // count votes for candidate_index
      char nVotesChar = tallyBaseStr.charAt(j);
      // convert from base to base 10
      int nVotes = Integer.parseInt(String.valueOf(nVotesChar), base);
      nonBlank += nVotes;
      // get candidate name from the list of candidates
      String candName = getCandidateNames().get(index);
      // and append the number of votes in the candidate
      s.append(candName).append(" : ").append(nVotes).append("\n");
      LOG.log(Level.INFO, "votes for candidate {0}(index {1}) = {2}",
              new Object[]{candName,
                index, nVotes});
    }
    int blankVotes = getVotersWhoVoted() - nonBlank;
    s.append("TOTAL: ").append(nonBlank).append(" votos, ");
    s.append(blankVotes).append(" em branco").append("\n");
    return s.toString().trim(); // trim to remove useless \n
  }

  // TODO: passar isto para uma classe utils
  private String paddingZeros(String n, int strLength) {
    StringBuilder sb = new StringBuilder();

    // append zeros
    for(int toprepend = strLength-n.length(); toprepend > 0; toprepend--) {
      sb.append('0');
    }
    // append string n
    sb.append(n);
    return sb.toString();
  }
}
