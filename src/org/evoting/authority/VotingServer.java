/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.authority;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.evoting.exception.VotingSchemeException;
import org.evoting.schemes.KOutOfLVoting;
import org.evoting.schemes.OneOutOfLVoting;
import org.evoting.schemes.Voting;
import org.evoting.schemes.YesNoVoting;

/**
 *
 * @author nc
 */
public class VotingServer {

  private Voting voting;
  private KeyPair keyPair;
  private static final Logger LOG = Logger.getLogger(VotingServer.class.
          getName());

  public VotingServer(Voting vot, KeyPair kP) throws VotingSchemeException,
          KeyException {
    this.voting = vot;
    this.keyPair = kP;
    // modulo n is not valid
    canEncrypt(); // throws exception if it cannot encrypt
  }

  public Voting getVoting() {
    return voting;
  }

  public void canEncrypt() throws VotingSchemeException, KeyException {
    if (voting == null) {
      throw new VotingSchemeException("No voting scheme defined");
    }
    if (keyPair == null || keyPair.getPublic() == null) {
      throw new KeyException("No public key assigned");
    }
    else {
      switch (voting.getCode()) {
        case OneOutOfLVoting.CODE:

          break;
        case KOutOfLVoting.CODE:
          BigInteger tMaxPlusOne = new BigInteger(Integer.
                  toString(((KOutOfLVoting) voting).calcMaxT() + 1));

          PaillierPublicKey pub = (PaillierPublicKey) keyPair.getPublic();
          // base > nrVoters
          if (!((KOutOfLVoting) voting).isBaseOK()) {
            throw new VotingSchemeException(
                    "Base must be greater than the number of voters");
          }
          // n >= Tmax + 1
          if (!(pub.getN().compareTo(tMaxPlusOne) >= 0)) {
            throw new VotingSchemeException(
                    "Modulo n must be greater or equal than Tmax + 1.");
          }
          break;
        case YesNoVoting.CODE:
          // i dont think there's any restriction on Yes/No...
          break;
        default:
          throw new VotingSchemeException("No such voting scheme as " + voting.
                  getClass().getCanonicalName());
      }
    }
  }

  /**
   * Starts a new voting <p> This voting ends either when the timeout is
   * reached, or the number of votes received reachs the maximum allowed defined
   * in {@link Voting}
   *
   * @param timeout
   * @param port
   * @throws IOException
   * @throws InvalidKeyException
   * @throws PaillierException
   */
  public void startVoting(int timeout, int port) throws IOException,
    InvalidKeyException, PaillierException {
    ServerSocket server = new ServerSocket(port);
    // set the server timeout in miliseconds
    server.setSoTimeout(timeout);

    LOG.log(Level.INFO, "Voting started!");

    // this loop breaks when timeout is reached
    while (true) {
      // accepts any client that connects to me
      // but each voter must be validated in its thread!
      try {
        Socket voter = server.accept();
        // if the number of max voter has been reached, break
        // TODO: improve this
        if (!voting.canAcceptMoreVotes()) {
          LOG.log(Level.INFO,
                  "Cannot receive more votes. Max number of voters reached");
          break;
        }
        LOG.log(Level.INFO, "Voter connected");
        // start the voter thread
        TServer voterThread = new TServer(voter, keyPair, voting);
        voterThread.start();
      }
      catch (SocketTimeoutException ex) {
        LOG.log(Level.INFO, "SocketTimeout reached. Voting ended!");
        // voting ended. exit while(1) loop
        break;
      }
    }

  }
}
