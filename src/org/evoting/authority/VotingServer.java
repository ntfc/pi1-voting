/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.authority;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author nc
 */
public class VotingServer extends Thread {
  private ServerSocket serverSocket;
  private int port;
  private int nCandidates, base;
  private int nVoters;

  public VotingServer(int port, int nCandidates, int base) {
    this.port = port;
    this.nCandidates = nCandidates;
    this.base = base;
  }


  public VotingServer(int port, int nrCands, int base, int voters) {
    this.port = port;
    this.nCandidates = nrCands;
    this.base = base;
    this.nVoters = voters;
  }

  @Override
  public void run() {
    try {
      startServer();
    }
    catch (IOException ex) {
      System.err.println("Error starting server. Server may not be running anymore.");
    }
  }

  private void startServer() throws IOException {
    this.serverSocket = new ServerSocket(port);
    int nrClientes = 0;
    while(true) {
      Socket socket = this.serverSocket.accept();
      nrClientes++;
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
