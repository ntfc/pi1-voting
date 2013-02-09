/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.schemes;

import java.math.BigInteger;

/**
 * This class implements the ballot that each voter sends to the authority.
 * @author nc
 */
public class Ballot {
  private BigInteger[] votes;

  public Ballot(int nrCands) {
    this.votes = new BigInteger[nrCands];
  }

  public BigInteger getCandidateVote(int cand) {
    if(cand >= votes.length) {
      return null;
    }
    return this.votes[cand];
  }

  /**
   * Add a encrypted vote to the bulletin
   * <p>
   * Vote must come already encrypted
   * @param index
   * @param voteEnc
   * @return
   */
  public void addVote(int index, BigInteger voteEnc) {
    this.votes[index] = voteEnc;
  }
  
  public BigInteger[] getVotes(){
    return this.votes;
  }
}
