/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.voter;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.numbers.CryptoNumbers;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.cssi.paillier.spec.PaillierPublicKeyBetaSpec;
import org.evoting.exception.NumberOfVotesException;
import org.evoting.exception.VariableNotSetException;
import org.evoting.exception.VotingSchemeException;
import org.evoting.schemes.Ballot;
import org.evoting.schemes.Voting;
import org.evoting.zkp.InteractiveProof;
import org.evoting.zkp.Proof;
import org.evoting.zkp.ZKPValidMProverInt;
import org.evoting.zkp.ZKPValidMProverNonInt;
import org.evoting.zkp.ZKPVotedKProver;
import org.utils.ByteUtils;
import org.utils.DataStreamUtils;

/**
 * Class that defines a voter and its operations
 * <p>
 * TODO: close {@link DataStreamUtils}
 * TODO: support more than just {@link Paillier}
 *
 */
public class VoterClient {

  private Socket socket;
  private DataStreamUtils dsu;
  private PublicKey publicKey;
  private Paillier paillier;
  private Voting voting;
  private static final Logger LOG = Logger.getLogger(VoterClient.class.getName());
  private BigInteger voterID;

  public VoterClient(Socket soc, BigInteger voterid) throws IOException {
    this.socket = soc;
    this.dsu = new DataStreamUtils(socket.getInputStream(), socket.
      getOutputStream());
    this.paillier = new PaillierSimple();
    this.voterID = voterid;
  }

  /**
   * Return the voting scheme instance
   *
   * @return
   */
  public Voting getVoting() {
    return voting;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Set up a voting
   * <p>
   * In this method, the voter receive every necessary information from the
   * authority
   * <br>
   * It receives the voting scheme, the number of voters and candidates and the
   * {@link PublicKey}
   *
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidKeySpecException
   */
  public void setUpVoting() throws NoSuchAlgorithmException,
    NoSuchProviderException, InvalidKeySpecException,
    VotingSchemeException {
    // receive voting properties from server
    try {

      // first, create the voting
      voting = new Voting();

      //------- receive voting properties
      voting.readVotingProperties(dsu);

      //------- receive voting candidates
      voting.readVotingCandidates(dsu);

      // receive public key
      byte[] pubKeyEnc = dsu.readBytes();
      //-------------------------
      KeyFactory keyFactory = KeyFactory.getInstance("Paillier", "CSSI");
      PaillierPublicKeyBetaSpec paiSpec = new PaillierPublicKeyBetaSpec(
        pubKeyEnc);
      this.publicKey = keyFactory.generatePublic(paiSpec);
      //-------------------------
    }
    catch (IOException ex) {
      System.err.println(ex.getMessage());
    }
  }

  public Ballot createBallot(int... votes) {
    // TODO: seria o metodo usado com ZKP nao interactivo..
    return null;
  }
  /**
   *
   * @param votes The array containing the indexes of the voter options
   */
  public void submitVote(int... votes) throws NumberOfVotesException,
    VotingSchemeException, InvalidKeyException, IOException, PaillierException, VariableNotSetException, NoSuchAlgorithmException {

    int ballotSize = voting.getL() + voting.getK();
    // sum 1 if voted for candidate i, 0 otherwise
    // NOTE: array size is getL() + getK() because of dummy votes
    int[] options = new int[ballotSize];
    Arrays.fill(options, 0); // default option is 0
    // put 1's where the voter voted
    for(int i = 0; i < votes.length; i++) {
      options[votes[i]] += 1; // WARNING: using += 1 just to be able to cheat
    }
    // put the necessary blank votes in the dummy votes
    int blank = voting.getK() - votes.length;
    for(int i = voting.getL(); i < (voting.getL() + blank) ; i++) {
      options[i] = 1;
    }
    System.err.println("Ballot = " + Arrays.toString(options));

    BigInteger[] arrayWithR = new BigInteger[ballotSize];
    // this array contains 1's and 0's: 1 if voted for candidate i, 0 otherwise

    // send vote and create ZKP for each voting option
    // DUMMY VOTES ARE DEALED IN THE NEXT LOOP
    for(int i = 0; i < voting.getL(); i++) {
      // encrypt vote
      BigInteger r = CryptoNumbers.genRandomZN(((PaillierPublicKey)publicKey).getN(), new SecureRandom());
      BigInteger m = BigInteger.valueOf(options[i]);
      BigInteger C = voting.getCipher().enc(publicKey, m, r);
      
      //save r value
      arrayWithR[i] = r;
      
      // send vote
      dsu.writeBigInteger(C);
      // zkp
      ZKPValidMProverNonInt niZKP = new ZKPValidMProverNonInt(voting.getS(), (PaillierPublicKey)publicKey);
      InteractiveProof p = (InteractiveProof) niZKP.generateProof(C, m, r, voterID);
      // send NI proof
      dsu.writeBytes(p.getProofAsByteArray());
    }
    // deal with dummy votes now
    for(int i = voting.getL(); i < ballotSize; i++) {
      BigInteger r = CryptoNumbers.genRandomZN(((PaillierPublicKey)publicKey).getN(), new SecureRandom());
      BigInteger m = BigInteger.valueOf(options[i]);
      BigInteger C = voting.getCipher().enc(publicKey, m, r);

      //save r value
      arrayWithR[i] = r;

      // send vote
      dsu.writeBigInteger(C);
      // zkp
      ZKPValidMProverNonInt niZKP = new ZKPValidMProverNonInt(voting.getS(), (PaillierPublicKey)publicKey);
      InteractiveProof p = (InteractiveProof) niZKP.generateProof(C, m, r, voterID);
      // send NI proof
      dsu.writeBytes(p.getProofAsByteArray());
    }
    
    //zkpVotedkProver
    ZKPVotedKProver kProver = new ZKPVotedKProver(publicKey);
    
    //gen step 1
    byte[] step1KProver = kProver.generateStep1(arrayWithR);
    
    //send step 1
    dsu.writeBytes(step1KProver);
    
  }
}
