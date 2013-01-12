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
import org.utils.DataStreamUtils;

/**
 *
 * @author nc
 */
public class OneOutOfLVoting extends Voting {

  private int base;

  /**
   * Only used by the voter Default base is 10
   */
  public OneOutOfLVoting() {
    this(new ArrayList<String>(), -1, 10);
  }

  /**
   * Create a 1-out-of-L voting <p> L is the number of candidates, or the size
   * of the list of candidates
   *
   * @param cands
   * @param voters
   * @param base
   */
  public OneOutOfLVoting(List<String> cands, int voters, int base) {
    super(cands.size(), voters);
    super.candidateNames = cands;
    this.base = base;
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
   * Creates a String with the voting results <p> It display how many votes each
   * candidate had
   *
   * @param tallyDec
   * @return
   */
  @Override
  public String votingResults(BigInteger tallyDec) {

    StringBuilder s = new StringBuilder();
    String result = String.format("%0" + (nrCandidates+1) + "d", tallyDec);
    int index = 1;

    s.append("Resultados:\n");
            
    s.append("Votos em branco: ").append(result.charAt(nrCandidates));
    s.append("\n");
    for (int i = (nrCandidates - 1); i >= 0; i--) {
      s.append("Opção ").append(index).append(" : ").append(result.charAt(i));
      s.append("\n");
      index++;
    }
    return s.toString();
  }
}
