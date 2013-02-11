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

/**
 * This class implements the ballot that each voter sends to the authority.
 * @author nc
 */
public class Ballot {
  private Map<Integer, BigInteger> votes;
  private Map<Integer, Proof> proofs;
  private int size;

  public Ballot(int nrCands, int nrOpts) {
    this.votes = new TreeMap<>();
    this.proofs = new TreeMap<>();
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
    System.err.println("Vote byte[] size: " + voteEnc.toByteArray().length);
    System.err.println("Proof byte[] size: " + p.getProofEncoded().length);
    this.votes.put(candIndex, voteEnc);
    this.proofs.put(candIndex, p);
  }

  public BigInteger getVote(int candIndex) {
    return this.votes.get(candIndex);
  }

  public Proof getProof(int candIndex) {
    return this.proofs.get(candIndex);
  }

  public List<BigInteger> getVotes() {
    return new ArrayList<>(this.votes.values());
  }
}
