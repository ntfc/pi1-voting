/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.schemes;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import org.cssi.paillier.cipher.PaillierException;
import org.evoting.exception.VotingSchemeException;
import org.utils.DataStreamUtils;

/**
 *
 * @author nc
 */
public class OneOutOfLVoting extends Voting {

  private int base;
  private String code;
  /**
   * Only used by the voter Default base is 10
   */
  public OneOutOfLVoting() throws VotingSchemeException {
    this(new ArrayList<String>(), -1, 10);
    code = "ooolV";
  }

  /**
   * Create a 1-out-of-L voting <p> L is the number of candidates, or the size
   * of the list of candidates
   *
   * @param cands
   * @param voters
   * @param base
   */
  public OneOutOfLVoting(List<String> cands, int voters, int base) throws VotingSchemeException {
    super(cands.size(), voters);
    // TODO: create more exceptions (OneOutOfLException, etc)
    if(base <= voters) {
      throw new VotingSchemeException("Base must be greater than base. "
              + "Found base = " + base + " and nVoters = " + voters);
    }
    super.candidateNames = cands;
    this.base = base;
    code = "ooolV";
  }

  public int getL() {
    return candidateNames.size();
  }

  public int getBase() {
    return base;
  }

  public int getMaxM() {
    return base ^ (nrCandidates - 1);
  }

  public int getMaxT() {
    return nrVoters * getMaxM();
  }


  /**
   * In a 1-out-of-L, the only common property is the base
   *
   * @param dsu
   * @throws IOException
   */
  @Override
  public void sendVotingProperties(DataStreamUtils dsu) throws IOException {
    // send base number
    dsu.writeInt(base);
  }

  /**
   * Assign the base number <p> This method is used only by the voters
   *
   * @param dsu
   * @throws IOException
   */
  @Override
  public void readVotingProperties(DataStreamUtils dsu) throws IOException {
    // read base
    this.base = dsu.readInt();
  }

  /**
   * TODO: finish this method
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
    throw new UnsupportedOperationException("Not supported yet.");
  }

  /**
   * Creates a String with how many votes each candidate had
   * <p>
   * How does it work?
   * <b>1.</b> the length of tally.toString() must be equal to nrCandidates<br>
   * <b>1. a)</b> if it's not, it adds the necessary zeros to the left of the string.
   * <b>2.</b> the number of blank votes are calculated in the end, by doing
   * votes.size() - nonBlankVotes
   * <b>3.</b> The number of votes in candidate x_(nrCandidates-1) is in the
   * first position of the string, and so on..
   *
   * @param tallyDec
   * @return
   */
  @Override
  public String votingResults(BigInteger tallyDec) {
    StringBuilder s = new StringBuilder();

    // if needed, adds zeros on the left to tallyDec string
    String result = String.format("%0" + (nrCandidates) + "d", tallyDec);

    s.append("Resultados:\n");

    int nonBlankVotes = 0;

    for (int i = (nrCandidates - 1), index = 1; i >= 0; i--, index++) {
      int nVotes = result.charAt(i) - '0'; // http://stackoverflow.com/q/4221225
      nonBlankVotes += nVotes; // add votes in candidate to the total non blank votes
      s.append(super.candidateNames.get(index-1)).append(" : ").append(nVotes).append("\n");
    }
    int blank = votes.size() - nonBlankVotes;
    s.append("TOTAL: ");
    s.append(nonBlankVotes).append(" votos + ").append(blank).append(" em branco\n");
    return s.toString();
  }

    @Override
    public String getCode() {
        return code;
    }
}
