/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evonting.voter;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.cssi.paillier.spec.PaillierPublicKeyBetaSpec;
import org.cssi.paillier.spec.PaillierPublicKeySpec;
import org.cssi.provider.CssiProvider;
import org.utils.DataStreamUtils;

/**
 *
 * @author nc
 */
public class VoterClient {
  private static final Logger log = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

  public static void main(String[] args) {
    try {
	    Socket s = new Socket("localhost",4567);
      // add provider
      Security.addProvider(new CssiProvider());
      DataStreamUtils dsu = new DataStreamUtils(s.getInputStream(), s.getOutputStream());

      int nCand = dsu.readInt();
      int base = dsu.readInt();

      byte[] pubKeyEnc = dsu.readBytes();
      KeyFactory keyFact = KeyFactory.getInstance("Paillier", "CSSI");
      PaillierPublicKeyBetaSpec spec = new PaillierPublicKeyBetaSpec(pubKeyEnc);
      PaillierPublicKey pubKey = (PaillierPublicKey) keyFact.generatePublic(spec);
      System.out.println("n = " + pubKey.getN());
      Paillier paillier = new PaillierSimple();

	    String test;
      BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
	    //while((test = stdIn.readLine()) != null) {
      
      System.out.print("Escolher voto\n");
      for(int i = 1; i <= nCand; i++) {
        System.out.println("Opção " + i);
      }

        Integer voteI = Integer.valueOf(stdIn.readLine());
        BigInteger baseBI = new BigInteger(Integer.toString(base));
        BigInteger vote = baseBI.pow(voteI);
        System.out.println("Base = " + base + ",voto=" + voteI + "Voto final = " + vote);
        BigInteger c = paillier.enc(pubKey, vote, new SecureRandom());
        dsu.writeBigInteger(c);
        System.out.println("Enviado: " + c);
	    //}
    }
    catch (Exception e){
      log.log(Level.SEVERE, e.getMessage(), e);
    }
  }

}
