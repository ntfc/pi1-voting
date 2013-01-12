/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.authority;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.paillier.cipher.PaillierException;
import org.evoting.schemes.Voting;

/**
 *
 * @author nc
 */
public class VotingServer {

  private Voting voting;
  private KeyPair keyPair;
  private static final Logger LOG = Logger.getLogger(VotingServer.class.
          getName());

  public VotingServer(Voting vot, KeyPair kP) {
    this.voting = vot;
    this.keyPair = kP;
  }

  public Voting getVoting() {
    return voting;
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
