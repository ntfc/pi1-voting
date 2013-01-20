/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.schemes;

import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;

/**
 * This class implements the ballot that each voter sends to the authority.
 * @author nc
 */
public class Ballot {
  private Map<Integer, BigInteger> votes; // candidate -> vote

  public Ballot() {
    this.votes = new TreeMap<Integer, BigInteger>();
  }

  public BigInteger getCandidateVote(int cand) {
    return this.votes.get(cand);
  }

  public boolean containsVote(int cand) {
    return this.votes.containsKey(cand);
  }

  /**
   * Add a encrypted vote to the bulletin
   * <p>
   * Vote must come already encrypted
   * @param index
   * @param voteEnc
   * @return
   */
  public BigInteger addVote(int index, BigInteger voteEnc) {
    return this.votes.put(index, voteEnc);
  }
}
