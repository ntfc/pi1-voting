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
import java.security.SecureRandom;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.evoting.exception.NumberOfVotesException;
import org.evoting.exception.VotingSchemeException;
import org.utils.DataStreamUtils;

/**
 *
 */
public class YesNoVoting extends Voting {

  public static final int CODE = 0x74;

  /**
   * Used only by the voter
   */
  public YesNoVoting() {
    super(2, -1); // 2 candidates, unknown number of candidates
  }

  /**
   * Create a new Yes/No voting scheme.
   * <p>
   * The maximum number of voter and the names of the two candidates must be
   * supplied
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

  @Override
  public int getCode() {
    return CODE;
  }

  /**
   * Determine who won this ellection
   * <p>
   * The received tally must be unencrypted
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

  @Override
  public Ballot createBallot(PublicKey key, int... votes) throws
          NumberOfVotesException,
          VotingSchemeException, InvalidKeyException, IOException,
          PaillierException {
    if (getCipher() == null) { // No cipher associated with voting
      throw new VotingSchemeException(
              "No encryption algorithm associated with voting scheme");
    }
    if (votes.length > 1) {
      throw new NumberOfVotesException(
              "Maximum number of votes allowed in Yes/No voting is one.");
    }
    // TODO: allow blank votes
    // TODO: consider Yes/No voting as 1-out-of-2 Voting?
    BigInteger vote = new BigInteger(Integer.toString(votes[0]));

    Ballot ballot = new Ballot();
    ballot.addVote(getCipher().enc(key, vote, new SecureRandom()));
    return ballot;

  }
}