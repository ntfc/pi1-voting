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
    this.votes = new ArrayList<>();
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

}
