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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.evoting.exception.VotingSchemeException;
import org.evoting.schemes.proofs.Proof;
import org.utils.ByteUtils;
import org.utils.DataStreamUtils;

/**
 * Class that defines the basics of a voting scheme
 * <p>
 * Every voting scheme must store the number of candidates, number of voters
 * allowed, a list with the candidate names and the number of received votes
 * <br>
 *
 * @author miltonnunes52
 */
public class Voting {
  private int nrCandidates; // this is L
  private int nrVoters;
  private List<String> candidateNames;
  //private List<Ballot> votes;
  private Map<Integer, Map<BigInteger, Proof>> votes;
  private Paillier cipher;
  private int votersWhoVoted = 0;
  private int invalidvotes = 0;
  private static final Logger LOG = Logger.getLogger(Voting.class.
    getName());
  public static final int CODE = 0x14;
  private int nrOptions; // this is K
  private BigInteger[] S; // set of allowed messages
  private VotingResult voteResults;

  /**
   * Create an empty voting scheme <p> This is used only by the voter
   */
  public Voting() {
    this(null, -1, -1, new ArrayList<String>(), null);
  }

  /**
   * Create a new K-out-of-L voting.
   * <p>
   * L is the lengths of the cands param
   * @param k
   * @param voters
   * @param cands
   */
  public Voting(Paillier cipher, int k, int voters, List<String> cands, BigInteger[] messages) {
    this.nrCandidates = cands.size();
    this.nrVoters = voters;
    this.candidateNames = cands;
    //this.votes = new LinkedList<>();
    this.votes = new HashMap<>();
    this.nrOptions = k;
    this.S = messages;
    this.cipher = cipher;
  }

  /**
   * Return the number of candidates
   *
   * @return
   */
  public int getNrCandidates() {
    return nrCandidates;
  }
  public int getL() { return nrCandidates;}
  public int getK() { return nrOptions; }
  private void setL(int l) { nrCandidates = l; }
  private void setK(int k) { nrOptions = k; }

  public Paillier getCipher() {
    return cipher;
  }

  public BigInteger[] getS() {
    return S;
  }
  public void setS(BigInteger[] s) {
    this.S = s;
  }
  
  public void addInvalidVote(){
    this.invalidvotes++;
  }

  public int getInvalidVotes(){
    return this.invalidvotes;
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
  public void sendVotingProperties(DataStreamUtils dsu) throws IOException {
    // send k
    dsu.writeInt(getK());
    // send l
    dsu.writeInt(getL());
    // send S
    dsu.writeBytes(ByteUtils.arrayBigIntegerToByte(getS()));
    // send cipher code
    dsu.writeInt(getCipher().getCODE());
  }

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
  public void readVotingProperties(DataStreamUtils dsu) throws IOException, VotingSchemeException {
    // read k
    setK(dsu.readInt());
    // read l
    setL(dsu.readInt());
    // read S
    setS(ByteUtils.byteToArrayBigInteger(dsu.readBytes()));
    // read cipher code
    int cipherCode = dsu.readInt();
    switch(cipherCode) {
      case PaillierSimple.CODE:
        setCipher(new PaillierSimple());
        break;
      default: // TODO: VotingSchemeException?
        throw new VotingSchemeException("No cipher with code " + cipherCode + " was found.");
    }
  }

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
  public void receiveBallot(Ballot ballot) {
    
    for(int i = 0; i < ballot.size(); i++) {
      if(votes.get(i) == null) {
        votes.put(i, new HashMap<BigInteger, Proof>());
      }
      // add ballot and proof
      votes.get(i).put(ballot.getVote(i), ballot.getProof(i));

    }
    addVoterWhoVoted();
  }

  /**
   * Used in interactive method
   * @param votes
   */
  public void receiveVotes(List<BigInteger> vs) {
    for(int i = 0; i < vs.size(); i++) {
      if(votes.get(i) == null) {
        votes.put(i, new HashMap<BigInteger, Proof>());
      }
      // add ballot
      votes.get(i).put(vs.get(i), null);      
    }
    addVoterWhoVoted();
  }
  
  public void addVoterWhoVoted(){
    votersWhoVoted++;
  }
  

  /**
   * Multiply all votes received and returned the tally
   * <p>
   * NOTE: Tally is not decrypted!!!
   *
   * @param key
   * @param candIndex
   * @return The unencrypted tally of all votes in candidate candIndex
   * @throws InvalidKeyException
   * @throws PaillierException
   */
  private BigInteger tallying(PrivateKey key, int candIndex) throws InvalidKeyException,
          PaillierException,
          VotingSchemeException {
    if(candIndex >= (getL() + getK())) {
      throw new VotingSchemeException("Candidate index must be between 0 and nrCandidates + nrOptions");
    }
    if(votes.isEmpty()){
      return BigInteger.ZERO;
    }
    Map<BigInteger, Proof> candVotes = votes.get(candIndex);
    return getCipher().mult(key, candVotes.keySet());
  }

  /**
   * Returns an array with the results of each candidate. Also, it includes the
   * blank votes.
   * <p>
   * In the voting results we can see how many votes each candidate got
   *
   * @param key
   * @return An array containing the results for each candidate, and the blank
   * votes in the last position
   */
  public VotingResult votingResults(PrivateKey key) throws InvalidKeyException,
    PaillierException, VotingSchemeException {
      VotingResult results = new VotingResult();
      
      for (int i = 0; i < nrCandidates; i++) {
        // number of votes for candidate
        BigInteger candTallyEnc = tallying(key, i);
        BigInteger res = cipher.dec(key, candTallyEnc);
        results.addResult(res, i);
      }
      //add blank votes
      List<BigInteger> blankVotes = new ArrayList<>();
      for(int i = getL(); i < (getL() + getK()); i++) {
        BigInteger blankTallyEnc = tallying(key, i);
        blankVotes.add(blankTallyEnc);
      }
      BigInteger blankTotalEnc = getCipher().mult(key, blankVotes);
      results.addResultBlankVotes(getCipher().dec(key, blankTotalEnc));
      
      //add invalid votes
      results.addResultInvalidVotes(BigInteger.valueOf(invalidvotes));
      return results;
  }

}
