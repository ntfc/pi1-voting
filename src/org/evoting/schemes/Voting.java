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
import java.util.ArrayList;
import java.util.List;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.interfaces.PaillierPrivateKey;
import org.evoting.exception.NumberOfVotesException;
import org.evoting.exception.VotingSchemeException;
import org.utils.DataStreamUtils;

/**
 * Class that defines the basics of a voting scheme
 * <p>
 * Every voting scheme must store the number of candidates, number of voters
 * allowed, a list with the candidate names and the number of received votes
 * <br>
 * TODO: DONT USE A LIST TO STORE CANDIDATE NAMES NOR THE VOTES
 *
 * @author miltonnunes52
 */
public abstract class Voting {
  /*
   * these variables are protected so that they can be accessible only from the
   * classes in this package
   */

  protected int nrCandidates; // this is L
  protected int nrVoters;
  protected List<String> candidateNames;
  //protected List<BigInteger> votes;
  protected List<Ballot> votes;
  private Paillier cipher; //TODO: add constructor with cipher as param
  private int votersWhoVoted = 0;

  /**
   * Create an empty voting scheme <p> This is used only by the voter
   */
  public Voting() {
    this(-1, -1);
  }

  /**
   * Create a voting scheme with
   * <code>cands</code> candidates and a maximum of
   * <code>voters</voters> voters allowed
   *
   * @param cands Number of candidates
   * @param voters Number of voters
   */
  public Voting(int cands, int voters) {
    this.nrCandidates = cands;
    this.nrVoters = voters;
    // initializate everything here
    this.candidateNames = new ArrayList<String>();
    this.votes = new ArrayList<Ballot>();
  }

  /**
   * Create a voting scheme with
   * <code>cands.size()</code> candidates and a maximum of
   * <code>voters</code> allowed.
   * <code>cands</code> contains the names of the candidates
   *
   * @param voters
   * @param cands
   */
  public Voting(int voters, List<String> cands) {
    this.nrCandidates = cands.size();
    this.nrVoters = voters;
    this.candidateNames = cands;
    this.votes = new ArrayList<Ballot>();
  }

  /**
   * Return the number of candidates
   *
   * @return
   */
  public int getNrCandidates() {
    return nrCandidates;
  }

  public Paillier getCipher() {
    return cipher;
  }

  public void setCipher(Paillier cipher) {
    this.cipher = cipher;
  }

  /**
   * Return the number of maximum voters allowed
   *
   * @return
   */
  public int getNrVoters() {
    return nrVoters;
  }

  public abstract int getCode();

  /**
   * Return the candidate names
   *
   * @return
   */
  public List<String> getCandidateNames() {
    return candidateNames;
  }

  /**
   * Obtain the number of votes already accounted
   *
   * @return
   */
  public int totalVotes() {
    return votes.size();
  }

  public int getVotersWhoVoted() {
    return votersWhoVoted;
  }

  /**
   * Did everyone already voted?
   *
   * @return
   */
  public boolean canAcceptMoreVotes() {
    return nrVoters > votersWhoVoted;
  }

  @Deprecated
  public boolean addCandidateNameAtIndex(String cand, int index) {
    if (index >= nrCandidates) {
      return false;
    }
    else {
      candidateNames.add(index, cand);
      //candidateNames[index] = cand;
      return true;
    }
  }

  /**
   * Send the voting properties to the voter.
   * <p>
   * All voting schemes must send the properties associated with itself. For
   * example, in {@link YesNoVoting} there are no properties to send. But in
   * {@link OneOutOfLVoting} the authority must send the base number. In more
   * complex schemes there may be even more properties to send
   * <br>
   * NOTE: this method must be only used by the authority
   *
   * @param dsu
   * @throws IOException
   */
  public abstract void sendVotingProperties(DataStreamUtils dsu) throws
          IOException;

  /**
   * Read the voting properties sent by the authority
   * <p>
   * Every voter must read the voting properties from the authority
   * <br>
   * NOTE: this method must be only used by the voters
   *
   * @param dsu
   * @throws IOException
   */
  // TODO: receive the cipher used
  public abstract void readVotingProperties(DataStreamUtils dsu) throws
          IOException;

  /**
   * Send the candidates to the voter
   * <p>
   * In order to vote, every voter must know that the options are. This method
   * sends the number of candidates and the and their names
   * <br>
   * NOTE: this method must be only used by the authority
   *
   * @param dsu
   * @throws IOException
   */
  public void sendVotingCandidates(DataStreamUtils dsu) throws IOException {
    // first, send number of candidates
    dsu.writeInt(nrCandidates);
    // then send the candidates
    for (String cand : candidateNames) {
      dsu.writeBytes(cand.getBytes());
    }
  }

  /**
   * Read the candidates info
   * <p>
   * Receives and assigns the number of candidates and their names
   * <br>
   * NOTE: this method must be only used by the voters
   *
   * @param dsu
   * @throws IOException
   */
  public void readVotingCandidates(DataStreamUtils dsu) throws IOException {
    // first, receive the number of candidates
    nrCandidates = dsu.readInt();
    // then receive the candidates names
    for (int i = 0; i < nrCandidates; i++) {
      String candName = new String(dsu.readBytes());
      this.candidateNames.add(i, candName);
    }
  }

  /**
   * Receive the ballot from the voter and add it to the list of received votes
   * <p>
   * NOTE: the votes in the ballot must already be encrypted!!
   *
   * @param vote
   * @return
   */
  public boolean receiveBallot(Ballot ballot) {
    votersWhoVoted++;
    return votes.add(ballot);
  }

  /**
   * Multiply all votes received and returned the tally
   * <p>
   * NOTE: Tally is not decrypted!!!
   *
   * @param key
   * @return The unencrypted tally of all votes
   * @throws InvalidKeyException
   * @throws PaillierException
   */
  public BigInteger tallying(PrivateKey key, int candIndex) throws InvalidKeyException,
          PaillierException,
          VotingSchemeException {
    if(candIndex >= nrCandidates) {
      throw new VotingSchemeException("Candidate index must be between 0 and nrCandidates-1");
    }
    BigInteger mult = BigInteger.ONE;
    BigInteger nSquare = ((PaillierPrivateKey) key).getN().pow(2);
    for (Ballot ballot : this.votes) {
      mult = mult.multiply(ballot.getCandidateVote(candIndex));
    }
    return mult.mod(nSquare);
  }

  /**
   * Determine who the winner of the voting was
   * <p>
   * TODO: considere the tie case
   * TODO: implement it on all subclasses
   *
   * @param key
   * @param tally
   * @return
   * @throws PaillierException
   * @throws InvalidKeyException
   */
  public abstract int winner(PrivateKey key, BigInteger tally) throws
          PaillierException, InvalidKeyException;

  /**
   * Creates a String with the voting results
   * <p>
   * In the voting results we can see how many votes each candidate got
   *
   * @param tally
   * @return
   */
  public abstract String votingResults(BigInteger tallyDec);

  /**
   * Receive a vote (or K votes) and creates a ballot
   * <p>
   * Each subclass must make sure the number of votes are lesser or equal than
   * the maximum number of votes allowed (on Yes/No, maximum is 1 and on
   * K-out-of-L maximum is K)
   * <p/>
   * @param key
   * @param votes
   * @throws NumberOfVotesException
   * @throws VotingSchemeException
   * @throws InvalidKeyException
   * @throws IOException
   */
  public abstract Ballot createBallot(PublicKey key, int... votes) throws
          NumberOfVotesException, VotingSchemeException, InvalidKeyException,
          IOException, PaillierException;
}
