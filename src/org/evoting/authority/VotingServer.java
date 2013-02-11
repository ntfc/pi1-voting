/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.authority;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.evoting.exception.VotingSchemeException;
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

  public VotingServer(Voting vot, KeyPair kP) throws VotingSchemeException,
          KeyException {
    this.voting = vot;
    //this.voting.setCipher(cipher);
    this.keyPair = kP;
    // modulo n is not valid
    canEncrypt(); // throws exception if it cannot encrypt
  }

  public Voting getVoting() {
    return voting;
  }

  public final void canEncrypt() throws VotingSchemeException, KeyException {
    if (voting == null) {
      throw new VotingSchemeException("No voting scheme defined");
    }
    if (keyPair == null || keyPair.getPublic() == null) {
      throw new KeyException("No public key assigned");
    }
  }

  /**
   * Starts a new voting
   * <p>
   * This voting ends either when the timeout is reached, or the number of votes
   * received reachs the maximum allowed defined in {@link Voting}
   *
   * @param timeout
   * @param port
   * @throws IOException
   * @throws InvalidKeyException
   * @throws PaillierException
   */
  public void startVoting(int timeout, int port) throws IOException,
          InvalidKeyException, PaillierException, InterruptedException {
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
        LOG.log(Level.INFO, "Voter connected");
        // start the voter thread
        TServer voterThread = new TServer(voter, keyPair, voting);
        voterThread.start();
        voterThread.join();
        if (!voting.canAcceptMoreVotes()) {
          //Close the socket,  the accept() call will throw a SocketException. No need for a break;
            server.close();
            LOG.log(Level.INFO,
                  "Cannot receive more votes. Max number of voters reached");
        }
        if(server.isClosed()) break;
      }
      catch (SocketTimeoutException ex) {
        LOG.log(Level.INFO, "SocketTimeout reached. Voting ended!");
        // voting ended. exit while(1) loop
        break;
      }
 
    }
     LOG.log(Level.INFO, "Voting ended");

  }
}
