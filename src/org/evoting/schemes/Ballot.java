/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.schemes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author nc
 */
public class Ballot {
  private List<BigInteger> votes;

  public Ballot() {
    this.votes = new ArrayList<BigInteger>();
  }
  public Ballot(List<BigInteger> votes) {
    this.votes = votes;
  }

  public List<BigInteger> getVotes() {
    return votes;
  }

  public boolean addVote(BigInteger vote) {
    return this.votes.add(vote);
  }

  /*public BigInteger tally() {
    BigInteger mult = BigInteger.ONE;
    for(BigInteger bb : this.votes) {
      mult = mult.multiply(bb);
    }
    return mult;
  }

  public BigInteger tally(BigInteger nSquare) {
    return tally().mod(nSquare);
  }*/

}
