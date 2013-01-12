/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.schemes;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.utils.DataStreamUtils;

/**
 *
 */
public class YesNoVoting extends Voting {

  /**
   * Used only by the voter
   */
  public YesNoVoting() {
    super(2, -1); // 2 candidates, unknown number of candidates
  }

  /**
   * Create a new Yes/No voting scheme. <p> The maximum number of voter and the
   * names of the two candidates must be supplied
   *
   * @param voters
   * @param cand1
   * @param cand2
   */
  public YesNoVoting(int voters, String cand1, String cand2) {
    super(2, voters);
    // TODO: this method is deprecated
    addCandidateNameAtIndex(cand1, 0);
    addCandidateNameAtIndex(cand2, 1);
  }

  /**
   * Determine who won this ellection <p> The received tally must be unencrypted
   *
   * @param key
   * @param tally
   * @return
   * @throws PaillierException
   * @throws InvalidKeyException
   */
  @Override
  public int winner(PrivateKey key, BigInteger tally) throws PaillierException,
          InvalidKeyException {
    BigInteger tallyDec = new PaillierSimple().dec(key, tally);
    // tally dec has now the sum of all the votes.
    // in a yes/no votation, the only possible values are 0 or 1
    // so, the decrypted tally contains the number of votes in the option 1

    if (tallyDec.intValue() > totalVotes()) // yes wins
    {
      return 1;
    }
    if (tallyDec.intValue() < totalVotes()) // no wins
    {
      return 0;
    }

    return -1; // in case of tie
  }

  @Override
  public String votingResults(BigInteger tally) {
    return "Finish votingResults()";
  }

  @Override
  public void sendVotingProperties(DataStreamUtils dsu) throws IOException {
    // No specific properties for Yes/No voting
  }

  @Override
  public void readVotingProperties(DataStreamUtils dsu) throws IOException {
    // No specific properties for Yes/No voting
  }
}