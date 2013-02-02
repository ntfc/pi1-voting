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
import org.evoting.schemes.KOutOfLVoting;
import org.evoting.schemes.Voting;
import org.evoting.zkp.ZKPProver;
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

  public VoterClient(Socket soc) throws IOException {
    this.socket = soc;
    this.dsu = new DataStreamUtils(socket.getInputStream(), socket.
      getOutputStream());
    this.paillier = new PaillierSimple();
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

      // first, receive the kind of voting that is taking place
      int votingType = dsu.readInt();

      switch (votingType) {
        case KOutOfLVoting.CODE:
          voting = new KOutOfLVoting();
          break;
        default:
          throw new VotingSchemeException("No such voting scheme");
      }

      //------- receive voting properties
      voting.readVotingProperties(dsu);
      // TODO: do this in readVotingProperties(); auth send the cipher being used
      voting.setCipher(new PaillierSimple());

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

  public void submitBallot(Ballot ballot) throws IOException {
    if (ballot == null) {
      //TODO: throw exception
    }
    // send the votes
    // number of votes is always equal to the number of candidates

    for (int i = 0; i < voting.getNrCandidates(); i++) {
      // first, the voter sends the encrypted vote
      dsu.writeBigInteger(ballot.getCandidateVote(i));
      // then, he proves that the message is encrypted in the allowed set of messages
    }
  }

  /**
   *
   * @param votes The array containing the indexes of the voter options
   */
  public void submitVote(int... votes) throws NumberOfVotesException,
    VotingSchemeException, InvalidKeyException, IOException, PaillierException, VariableNotSetException {

    // sum 1 if voted for candidate i, 0 otherwise
    int[] options = new int[voting.getNrCandidates()];
    Arrays.fill(options, 0); // default option is 0
    // put 1's where the voter voted
    for(int i = 0; i < votes.length; i++) {
      options[votes[i]] += 1; // WARNING: using += 1 just to be able to cheat
    }
    
    // this array contains 1's and 0's: 1 if voted for candidate i, 0 otherwise
    int[] optionsI = new int[voting.getNrCandidates()];
    Arrays.fill(optionsI, 0); // default option is 0
    // put 1's where the voter voted
    for(int i = 0; i < votes.length; i++) {
      optionsI[votes[i]] = 1;
    }

    // this array contains 1's and 0's: 1 if voted for candidate i, 0 otherwise
    BigInteger[] S = new BigInteger[]{BigInteger.ZERO, BigInteger.ONE};
    // send vote and create ZKP for each voting option
    for(int i = 0; i < options.length; i++) {
      // encrypt vote
      BigInteger r = CryptoNumbers.genRandomZN(((PaillierPublicKey)publicKey).getN(), new SecureRandom());
      BigInteger opt = BigInteger.valueOf(options[i]);
      BigInteger C = voting.getCipher().enc(publicKey, opt, r);
      
      // send vote
      dsu.writeBigInteger(C);
      // zkp
      ZKPProver zkp = new ZKPProver(S, (PaillierPublicKey)publicKey, i, C, r);

      // send step1
      byte[] stp1 = zkp.generateStep1(C, optionsI[i]);
      dsu.writeBytes(stp1);

      // receive step2
      byte[] challenge = dsu.readBytes();  
      zkp.receiveStep2(challenge);

    /// send step3
      byte[][] step3 = zkp.generateStep3();
      
      
      byte[] step31 = step3[0];
      dsu.writeBytes(step31);
      
      byte[] step32 = step3[1];
      dsu.writeBytes(step32);

    
    
    }
  }
}
