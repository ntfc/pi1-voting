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
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import org.cssi.paillier.cipher.PaillierException;
import org.evoting.exception.NumberOfVotesException;
import org.evoting.exception.VotingSchemeException;
import org.utils.DataStreamUtils;

/**
 *
 * @author nc
 */
public class KOutOfLVoting extends Voting {

  private static final Logger LOG = Logger.getLogger(KOutOfLVoting.class.
          getName());
  public static final int CODE = 0x14;
  private int k, l;

  /**
   * Only used by the voter Default K=1, base is 10
   */
  public KOutOfLVoting() throws VotingSchemeException {
    this(1, -1, new ArrayList<String>());
  }
  // L = cands.size()

  public KOutOfLVoting(int K, int voters, List<String> cands) throws
          VotingSchemeException {
    super(voters, cands);

    this.k = K;
    this.l = cands.size();

  }

  public int getK() {
    return k;
  }

  public int getL() {
    return l;
  }

  @Override
  public int getCode() {
    return CODE;
  }

  @Override
  public void sendVotingProperties(DataStreamUtils dsu) throws IOException {
    // send k
    dsu.writeInt(k);
    // send l
    dsu.writeInt(l);
  }

  @Override
  public void readVotingProperties(DataStreamUtils dsu) throws IOException {
    // read k
    k = dsu.readInt();
    // read l
    l = dsu.readInt();
  }

  /**
   * Create a {@link Ballot} for the voter.
   *
   * @param key
   * @param votes The candidates in which the voter voted
   * @return
   * @throws NumberOfVotesException
   * @throws VotingSchemeException
   * @throws InvalidKeyException
   * @throws IOException
   * @throws PaillierException
   */
  @Deprecated
  @Override
  public Ballot createBallot(PublicKey key, int... votes) throws
          NumberOfVotesException,
          VotingSchemeException, InvalidKeyException, IOException,
          PaillierException {
    if (getCipher() == null) { // No cipher associated with voting
      throw new VotingSchemeException(
              "No encryption algorithm associated with voting scheme");
    }
    // TODO: ZKP must take care of this?
    if (votes.length > getK()) {
      throw new NumberOfVotesException(
              "Maximum number of votes allowed in K-out-of-L is K.");
    }
    Ballot ballot = new Ballot(nrCandidates);
    // add the options choosen by the voter
    for (int vv : votes) {
      vv--; // voting option must be in [0..L-1]
      // voting option is one
      BigInteger voteEnc = getCipher().enc(key, BigInteger.ONE,
                                           new SecureRandom());
      // add to the ballot
      ballot.addVote(vv, voteEnc);
    }
    // the other options are blank = 0
    for (int i = 0; i < nrCandidates; i++) {
      // no vote registered for candidate i
      if (ballot.getCandidateVote(i) == null) {
        // add blank vote
        BigInteger blank = getCipher().enc(key, BigInteger.ZERO,
                                           new SecureRandom());
        ballot.addVote(i, blank);
      }
    }
    return ballot;
  }

  @Override
  public BigInteger[] votingResults(PrivateKey key) throws InvalidKeyException,
          PaillierException, VotingSchemeException {
    BigInteger[] results = new BigInteger[nrCandidates];
    for (int i = 0; i < nrCandidates; i++) {
      // number of votes for candidate
      BigInteger candTallyDec = tallying(key, i);
      BigInteger candTally = getCipher().dec(key, candTallyDec);
      results[i] = candTally;
    }
    return results;
  }
}
