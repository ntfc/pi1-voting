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
import java.util.ArrayList;
import java.util.List;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.interfaces.PaillierPublicKey;
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
    throw new UnsupportedOperationException("Not supported yet.");
  }

  @Override
  public int winner(PrivateKey key, BigInteger tally) throws PaillierException,
          InvalidKeyException {
    throw new UnsupportedOperationException("Not supported yet.");
  }

  // TODO: the winners are the K candidates with the most votes
  @Override
  public String votingResults(BigInteger tallyDec) {
    StringBuilder s = new StringBuilder();

    // if needed, adds zeros on the left to tallyDec string
    String result = String.format("%0" + (nrCandidates) + "d", tallyDec);

    s.append("Resultados:\n");

    int nonBlankVotes = 0;

    for (int i = (nrCandidates - 1), index = 1; i >= 0; i--, index++) {
      int nVotes = result.charAt(i) - '0'; // http://stackoverflow.com/q/4221225
      nonBlankVotes += nVotes; // add votes in candidate to the total non blank votes
      s.append(super.candidateNames.get(index - 1)).append(" : ").append(nVotes).
              append("\n");
    }
    int blank = votes.size() - nonBlankVotes;
    s.append("TOTAL: ");
    s.append(nonBlankVotes).append(" votos + ").append(blank).append(
            " em branco\n");
    
    return s.toString();
  }

}
