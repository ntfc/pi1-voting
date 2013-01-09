/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.authority;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.provider.CssiProvider;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.interfaces.PaillierPrivateKey;
import org.cssi.paillier.interfaces.PaillierPublicKey;
/**
 *
 * @author nc
 */
public class VotingServer extends Thread {
  private ServerSocket serverSocket;
  private int port;
  private int nCandidates, base;
  private int nVoters;
  private ArrayList<BigInteger> votes;


  public VotingServer(int port, int nCandidates, int base) {
    this.port = port;
    this.nCandidates = nCandidates;
    this.base = base;
    this.votes = new ArrayList<BigInteger>();
  }


  public VotingServer(int port, int nrCands, int base, int voters) {
    this.port = port;
    this.nCandidates = nrCands;
    this.base = base;
    this.nVoters = voters;
    this.votes = new ArrayList<BigInteger>();
  }

  @Override
  public void run() {
    try {
          try {
              startServer();
          } catch (  NoSuchAlgorithmException | NoSuchProviderException ex) {
              Logger.getLogger(VotingServer.class.getName()).log(Level.SEVERE, null, ex);
          }
    }
    catch (IOException ex) {
      System.err.println("Error starting server. Server may not be running anymore.");
    }
  }

  private void startServer() throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
    this.serverSocket = new ServerSocket(port);
    int nrClientes = 0;
    while(true) {
      Security.addProvider(new CssiProvider()); 
      Socket socket = this.serverSocket.accept();
      nrClientes++;
      KeyPairGenerator kpGen = KeyPairGenerator.getInstance("Paillier", "CSSI");
      kpGen.initialize(1024);
      KeyPair kp = kpGen.generateKeyPair();
      TServer ts = new TServer(socket, kp, nVoters, nCandidates, votes);
      ts.start();
      System.out.println("Client accepted. Total: " + nrClientes);
    }
  }

  public void stopServer() throws IOException {
    this.serverSocket.close();
  }

  public boolean isRunning() {
    if(this.serverSocket == null)
      return false;
    else
      return !this.serverSocket.isClosed();
  }


  /*public static void main(String[] args) {
    try {
      ServerSocket ss = new ServerSocket(4567);
      ArrayList<BigInteger> votes = new ArrayList<>();
      // add provider
      Security.addProvider(new CssiProvider());
      // number of voters and candidates
      int nVoters = 2;
      int nCand = 5;
      // keypairgenerator for paillier
      // TODO: Nao devia ser feito aqui!! Fazer como no guiao do RSA
      KeyPairGenerator keyPG = KeyPairGenerator.getInstance("Paillier", "CSSI");
      // keypair
      keyPG.initialize(32);
      KeyPair keyPair = keyPG.generateKeyPair();
      int participants = 0;
      while(participants < nVoters) {
          Socket s = ss.accept();

          TServer tServer = new TServer(s, keyPair, nVoters, nCand, votes);
          tServer.start();
          participants++;

          // wait for completion of all threads
          try {
            tServer.join();
          }
          catch(InterruptedException e) {
            System.err.println(e.getMessage());
          }

      }

      Paillier paillier = new PaillierSimple();
      System.out.println("Election ended with " + votes.size() + " to count.");
      PaillierPrivateKey sk = (PaillierPrivateKey) keyPair.getPrivate();
      BigInteger n = sk.getN();
      BigInteger T = BigInteger.ONE;
      for(BigInteger v : votes) {
        T = T.multiply(v).mod(n.pow(2));
      }
      System.out.println("T = " + T);
      BigInteger dT;
      try {
        dT = paillier.dec(sk, T);
        System.out.println("D(T) = " + dT);
      }
      catch (PaillierException|InvalidKeyException ex) {
        System.err.println(ex.getMessage());
      }
      
    }
    catch(IOException|NoSuchAlgorithmException|NoSuchProviderException e) {
      System.err.println(e.getMessage());
    }
  }*/

}
