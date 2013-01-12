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
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.spec.PaillierPublicKeyBetaSpec;
import org.evoting.exception.VotingSchemeException;
import org.evoting.schemes.OneOutOfLVoting;
import org.evoting.schemes.Voting;
import org.evoting.schemes.YesNoVoting;
import org.utils.DataStreamUtils;

/**
 * Class that defines a voter and its operations <p> TODO: close
 * {@link DataStreamUtils} TODO: support more than just {@link Paillier}
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

  /**
   * Set up a voting <p> In this method, the voter receive every necessary
   * information from the authority<br> It receives the voting scheme, the
   * number of voters and candidates and the {@link PublicKey}
   *
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidKeySpecException
   */
  public void setUpVoting() throws NoSuchAlgorithmException,
          NoSuchProviderException, InvalidKeySpecException {
    // receive voting properties from server
    try {
      // TODO: em vez de mandar String, mandar so um codigo
      // first, receive the kind of voting that is taking place
      String votingType = new String(dsu.readBytes());

      //voting = new YesNoVoting();
      voting = new OneOutOfLVoting();

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
   * Submits the client vote
   *
   * @param cand
   * @param key
   */
  public void vote(Integer voteOption) throws IOException, PaillierException,
          InvalidKeyException, VotingSchemeException {
    BigInteger vote = null;
    if (voting == null) {
      throw new VotingSchemeException("No voting scheme defined");
    }

    if (voting instanceof YesNoVoting) {
      // yes/no voting
      vote = new BigInteger(Integer.toString(voteOption));
    }
    else if (voting instanceof OneOutOfLVoting) {
      // 1-out-of-L voting
      int base = ((OneOutOfLVoting) getVoting()).getBase();
      vote = new BigInteger(Integer.toString(base)).pow(voteOption);
    }
    // encrypt the vote
    BigInteger c = this.paillier.enc(publicKey, vote, new SecureRandom());
    // send vote
    dsu.writeBigInteger(c);

  }
}
