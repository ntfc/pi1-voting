/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.schemes;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.Map;
import java.util.TreeMap;
import org.cssi.paillier.cipher.PaillierException;

;

/**
 *
 * @author rafaelremondes
 */
public class VotingResult {

  private Map<Integer, BigInteger> results;
  private BigInteger invalidVotes;
  private BigInteger blankVotes;

  public VotingResult() {
    this.results = new TreeMap<>();
  }

  public int getResult(int opt) {
    return results.get(opt).intValue();
  }

  public Map<Integer, BigInteger> getResults() {
    return this.results;
  }

  public void addResult(BigInteger result, int index) throws PaillierException,
    InvalidKeyException {
    results.put(index, result);
  }

  public void addResultBlankVotes(BigInteger blank) {
    this.blankVotes = blank;
  }

  public void addResultInvalidVotes(BigInteger invalid) {
    this.invalidVotes = invalid;
  }

  public BigInteger getResultBlankVotes() {
    return this.blankVotes;
  }

  public BigInteger getResultInvalidVotes() {
    return this.invalidVotes;
  }
}
