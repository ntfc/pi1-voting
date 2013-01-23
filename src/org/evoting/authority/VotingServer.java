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
import java.security.KeyException;
import java.security.KeyPair;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.evoting.exception.VotingSchemeException;
import org.evoting.schemes.Voting;
import java.math.BigInteger;
import java.security.PrivateKey;

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
  /**
   * Return array of voting results
   * 
   * @throws VotingSchemeException
   * @throws InvalidKeyException
   * @throws PaillierException
   */
  public BigInteger[] votingResults() throws InvalidKeyException, PaillierException, VotingSchemeException{
    BigInteger[] res = new BigInteger[voting.getNrCandidates()];  
    PrivateKey privKey = keyPair.getPrivate();
    for(int i = 0; i <voting.getNrCandidates(); i++){
        BigInteger tally = voting.tallying(privKey, i);
                
        res[i] = new PaillierSimple().dec(privKey, tally);
    }
    return res;
  }
}
