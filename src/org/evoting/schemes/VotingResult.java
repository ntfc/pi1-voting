/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.schemes;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.evoting.exception.VotingSchemeException;
import org.evoting.schemes.proofs.Proof;

/**
 *
 * @author rafaelremondes
 */
public class VotingResult {
  
  private Paillier cipher;
  int nrCandidates;
  int k;
  Map<Integer,BigInteger> results;
  private Map<Integer, Map<BigInteger, Proof>> votes;
  int blankVotes;
  
  
  public VotingResult(Paillier cipher, int l, int k){
    this.cipher = cipher;
    this.k = k;
    this.nrCandidates = l;
  }
  
    private BigInteger tallying(PrivateKey key, int candIndex, int l, int k) throws InvalidKeyException,
          PaillierException,
          VotingSchemeException {
    if(candIndex >= (l + k)) { 
      throw new VotingSchemeException("Candidate index must be between 0 and nrCandidates + nrOptions");
    }
     if(votes.isEmpty()){
      return BigInteger.ZERO;
    }
    Map<BigInteger, Proof> candVotes = votes.get(candIndex);
    return cipher.mult(key, candVotes.keySet());
  } 
 
    
   public int getVotes(int candidate){
      return results.get(candidate).intValue();
   }
   
   public int getBlanks(){
     return this.blankVotes;
   }
     
   
   public List<Integer> winners(BigInteger[] results) {
    // returning List with the winners;
    List<Integer> winners = new ArrayList<>();
    int i = 0;
    Iterator it = this.results.keySet().iterator();
    while (it.hasNext() || i < k) {
      //Copy the results to the returning list
      winners.add((Integer) it.next());
    }
    return winners;
  }
   
  
   
  public void storeResults(BigInteger[] results){
    //auxiliar collection to store the results before and after being sorted
    Map<Integer, BigInteger> sortedResults = new TreeMap<>();
    int i;
    for (i = 0; i < results.length; i++) {
      // copy the results, key = Candidate, value = number of votes in BigInteger
      sortedResults.put(i, results[i]);
    }

    //Sort the rersults using a Comparator
    Comparator cpv = new valueComparator(sortedResults);
    sortedResults = new TreeMap<>(cpv);
    this.results = sortedResults;
  }
    
  public Map<Integer,BigInteger> getResults(){
    return this.results;
  }
  
   public void calculateResults(PrivateKey key, int l,  Map<Integer, Map<BigInteger, Proof>> votes) throws InvalidKeyException,
    PaillierException, VotingSchemeException {
    // blank votes are in the last position
     
    this.votes = votes;
    BigInteger[] results = new BigInteger[nrCandidates + 1];
    for (int i = 0; i < nrCandidates; i++) {
      // number of votes for candidate
      BigInteger candTallyDec = tallying(key, i,l,k);
      BigInteger candTally = cipher.dec(key, candTallyDec);
      
      results[i] = candTally;
    }
    // count blank votes
    results[l] = BigInteger.ZERO; // initial number of blank votes
    for(int i = l; i < (l + k); i++) {
      BigInteger blankTallyDec = tallying(key, i,l,k);
      BigInteger blanks = cipher.dec(key, blankTallyDec);
      results[l] = results[l].add(blanks);
    }  
    this.storeResults(results);
    this.blankVotes = results[l].intValue();
  }
}
  

