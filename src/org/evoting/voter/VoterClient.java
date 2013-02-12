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
import org.evoting.schemes.proofs.InteractiveProof;
import org.evoting.schemes.proofs.NonInteractiveProof;
import org.evoting.zkp.ZKPValidMProverInt;
import org.evoting.zkp.ZKPValidMProverNonInt;
import org.evoting.zkp.ZKPVotedKProver;
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
  private static final Logger LOG = Logger.
    getLogger(VoterClient.class.getName());
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

  /**
   * Given the voter options, creates a Ballot with the encrypted votes and the
   * respective proofs
   * <p>
   * <p/>
   * @param votes
   * @return
   * @throws PaillierException
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws VariableNotSetException
   */
  public Ballot createBallotNonInteractive(int... votes) throws
    PaillierException, InvalidKeyException, NoSuchAlgorithmException,
    VariableNotSetException {
    // cast publicKey
    PaillierPublicKey pub = (PaillierPublicKey) publicKey;
    BigInteger n = pub.getN();
    int ballotSize = voting.getL() + voting.getK();

    // ballot unencrypted, only with the voter options
    int[] options = new int[ballotSize];
    Arrays.fill(options, 0);
    // if voter voted for option i, set options[i] = 1, 0 otherwise
    for (int i = 0; i < votes.length; i++) {
      options[votes[i]] = 1; // TODO: test cheating here
    }
    // blank votes = K - nrOptionsSelected
    int nBlank = voting.getK() - votes.length;
    // put blank votes in the dummy votes
    for (int i = voting.getL(); i < (voting.getL() + nBlank); i++) {
      options[i] = 1;
    }
    LOG.log(Level.INFO, "Ballot = {0}", Arrays.toString(options));
    Ballot ballot = new Ballot(voting.getL(), voting.getK());

    // r_{ij} to prove that the ballot contains exactly K options selected
    BigInteger[] arrayWithR = new BigInteger[ballotSize];

    // ni zkp object
    ZKPValidMProverNonInt niZKP = new ZKPValidMProverNonInt(voting.getS(), pub);
    for (int i = 0; i < options.length; i++) {
      // encrypt vote
      BigInteger r = CryptoNumbers.genRandomZN(n, new SecureRandom());
      BigInteger m = BigInteger.valueOf(options[i]);
      BigInteger C = voting.getCipher().enc(pub, m, r);

      // save r_{ij}
      arrayWithR[i] = r;

      // generate NI-ZKP
      NonInteractiveProof proof = niZKP.generateProof(C, m, r, voterID);

      // add C and Proof to ballot
      ballot.addVote(i, C, proof);
    }

    // create the proof that he voted for exactly K candidates
    ZKPVotedKProver kZKP = new ZKPVotedKProver(publicKey);
    ballot.addR(kZKP.generateStep1(arrayWithR));

    return ballot;
  }

  public void submitBallot(Ballot b) throws IOException {
    for (int i = 0; i < b.size(); i++) {
      // send C
      dsu.writeBigInteger(b.getVote(i));
      // send proof
      dsu.writeBytes(b.getProof(i).getProofEncoded());
    }
    // send proof R
    dsu.writeBigInteger(b.getR());
  }

  /**
   * Submits the voter votes, <b>interactively</b>
   * <p>
   * <p/>
   * @param votes
   * @throws NumberOfVotesException
   * @throws VotingSchemeException
   * @throws InvalidKeyException
   * @throws IOException
   * @throws PaillierException
   * @throws VariableNotSetException
   * @throws NoSuchAlgorithmException
   */
  public void submitVoteInterative(int... votes) throws NumberOfVotesException,
    VotingSchemeException, InvalidKeyException, IOException, PaillierException,
    VariableNotSetException, NoSuchAlgorithmException {

    // cast publicKey
    PaillierPublicKey pub = (PaillierPublicKey) publicKey;
    BigInteger n = pub.getN();
    int ballotSize = voting.getL() + voting.getK();

    // ballot unencrypted, only with the voter options
    int[] options = new int[ballotSize];
    Arrays.fill(options, 0);
    // if voter voted for option i, set options[i] = 1, 0 otherwise
    for (int i = 0; i < votes.length; i++) {
      options[votes[i]] = 1; // TODO: test cheating here
    }
    // blank votes = K - nrOptionsSelected
    int nBlank = voting.getK() - votes.length;
    // put blank votes in the dummy votes
    for (int i = voting.getL(); i < (voting.getL() + nBlank); i++) {
      options[i] = 1;
    }
    LOG.log(Level.INFO, "Ballot = {0}", Arrays.toString(options));

    // r_{ij} to prove that the ballot contains exactly K options selected
    BigInteger[] arrayWithR = new BigInteger[ballotSize];

    ZKPValidMProverInt iZKP = new ZKPValidMProverInt(voting.getS(), pub);
    // send vote and create ZKP for each voting option
    for (int i = 0; i < ballotSize; i++) {
      // encrypt vote
      BigInteger r = CryptoNumbers.genRandomZN(pub.getN(), new SecureRandom());
      BigInteger m = BigInteger.valueOf(options[i]);
      BigInteger C = voting.getCipher().enc(pub, m, r);

      //save r value
      arrayWithR[i] = r;

      // send vote
      dsu.writeBigInteger(C);
      // zkp
      InteractiveProof step1 = iZKP.generateStep1(C, m, r);
      // send step1
      dsu.writeBytes(step1.getProofEncoded());

      // receive step2
      InteractiveProof step2 = new InteractiveProof(dsu.readBytes());
      iZKP.receiveStep2(step2);
      // send step3
      InteractiveProof[] step3 = iZKP.generateStep3();
      dsu.writeBytes(step3[0].getProofEncoded());
      dsu.writeBytes(step3[1].getProofEncoded());
    }
    //zkpVotedkProver
    ZKPVotedKProver kProver = new ZKPVotedKProver(pub);

    //gen step 1
    byte[] step1KProver = kProver.generateStep1(arrayWithR);

    //send step 1
    dsu.writeBytes(step1KProver);

  }
}
