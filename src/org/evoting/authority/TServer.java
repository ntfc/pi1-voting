/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.authority;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.utils.DataStreamUtils;

/**
 *
 * @author nc
 */
public class TServer extends Thread {
  private static final Logger log = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
  private Socket socket;
  private KeyPair keyPair;
  private int nVoters;
  private int nCandi;
  //private ArrayList<BigInteger> votes;
  private Votes votes;
  /**
   * Creates a new empty instance of <code>TServer</code>.
   */
  public TServer(Socket s, KeyPair kP, int voters, int cands, Votes votos) {
    this.socket = s;
    this.keyPair = kP;
    this.nVoters = voters;
    this.nCandi = cands;
    //this.votes = (ArrayList<BigInteger>) votes;
    this.votes = votos;
  }

  @Override
  public void run() {
    try {
      DataStreamUtils dsu = new DataStreamUtils(socket.getInputStream(), socket.getOutputStream());
      BigInteger n;

      try {
        // send election information to voter
        int base = 10; // base > voters
        int mMax = 10^(nCandi-1);
        int tMax = nVoters * mMax;
        dsu.writeInt(nCandi);
        dsu.writeInt(base);
        // send public key to the new connected client
        PublicKey p = this.keyPair.getPublic();
        PrivateKey sk = this.keyPair.getPrivate();
        System.out.println("n = " + ((PaillierPublicKey)p).getN());
        dsu.wryteBytes(p.getEncoded());
        // public key sent ----------------------
        Paillier paillier = new PaillierSimple();
        byte[] receivedVote;
        //while(true) {
        receivedVote = dsu.readBytes();
        votes.add(new BigInteger(receivedVote));
        System.out.println("Vote added");
          
         //no caso de chegar ao última votante apresenta resultados
        if(nVoters == votes.nVotes()){
           try {
               votes.printResults(nCandi);
           } catch (PaillierException ex) {
               Logger.getLogger(TServer.class.getName()).log(Level.SEVERE, null, ex);
           } catch (InvalidKeyException ex) {
               Logger.getLogger(TServer.class.getName()).log(Level.SEVERE, null, ex);
           }
         }
          
        //}
      }
      catch(IOException e) {
        log.log(Level.SEVERE, e.getMessage(), e);
      }
      finally {
        dsu.close();
      }

    }
    catch(IOException e) {
      log.log(Level.SEVERE, e.getMessage(), e);
    }
  }



}
