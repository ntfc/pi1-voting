/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.voter;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.spec.PaillierPublicKeyBetaSpec;
import org.evoting.exception.VotingSchemeException;
import org.evoting.schemes.Ballot;
import org.evoting.schemes.KOutOfLVoting;
import org.evoting.schemes.Voting;
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
      dsu.writeBigInteger(ballot.getCandidateVote(i));
    }
  }
}
