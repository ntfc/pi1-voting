/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.schemes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.evoting.schemes.proofs.NonInteractiveProof;
import org.evoting.schemes.proofs.Proof;
import org.utils.Pair;

/**
 * This class implements the ballot that each voter sends to the authority.
 * @author nc
 */
public class Ballot {
  private Map<Integer, Pair<BigInteger, Proof>> votes;
  private BigInteger R; // proof that he voted for K options
  private int size;

  public Ballot(int nrCands, int nrOpts) {
    this.votes = new TreeMap<>();
    this.size = nrCands + nrOpts;
  }

  public int size() { return size; }

  /**
   * Add an encrypted vote to the bulletin
   * <p>
   * Vote must come already encrypted
   * @param voteEnc
   * @return
   */
  public void addVote(int candIndex, BigInteger voteEnc) {
    this.addVote(candIndex, voteEnc, null);
  }

  /**
   * Add an encrypted vote to the bulletin, with its proof
   * @param voteEnc
   * @param p
   */
  public void addVote(int candIndex, BigInteger voteEnc, NonInteractiveProof p) {
    Pair<BigInteger, Proof> voteProof = new Pair<>(voteEnc, (Proof)p);
    this.votes.put(candIndex, voteProof);
  }

  public BigInteger getVote(int candIndex) {
    return this.votes.get(candIndex).getFirst();
  }

  public Proof getProof(int candIndex) {
    return this.votes.get(candIndex).getSecond();
  }

  public List<BigInteger> getVotes() {
    ArrayList<BigInteger> v = new ArrayList<>();
    for(Pair<BigInteger,Proof> p : votes.values()) {
      v.add(p.getFirst());
    }
    return v;
  }

  public void addR(BigInteger r) {
    this.R = r;
  }
  public void addR(byte[] r) {
    this.addR(new BigInteger(r));
  }

  public BigInteger getR() {
    return R;
  }
}
