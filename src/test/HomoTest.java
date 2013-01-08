package test;


import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import org.cssi.numbers.CryptoNumbers;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.interfaces.PaillierPrivateKey;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.cssi.provider.CssiProvider;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author nc
 */
public class HomoTest {

  public HomoTest() {
  }

  /**
   * @param args the command line arguments
   */
  public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, PaillierException, InvalidKeyException {
    Security.addProvider(new CssiProvider());
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("Paillier", "CSSI");
    kpGen.initialize(1024);
    KeyPair kp = kpGen.generateKeyPair();
    PaillierPublicKey p = (PaillierPublicKey) kp.getPublic();
    PaillierPrivateKey s = (PaillierPrivateKey) kp.getPrivate();


    Paillier paillier = new PaillierSimple();
    BigInteger m1 = new BigInteger("128"), m2 = new BigInteger("64");
    BigInteger k1 = CryptoNumbers.genRandomZStarN(p.getN(), new SecureRandom());
    BigInteger k2 = CryptoNumbers.genRandomZStarN(p.getN(), new SecureRandom());

    BigInteger c1 = paillier.enc(p, m1, k1);
    BigInteger c2 = paillier.enc(p, m2, k2);

    System.out.println("k1 = " + k1);
    System.out.println("k2 = " + k2);
    System.out.println("E(" + m1 + ") = " + c1);
    System.out.println("E(" + m2 + ") = " + c2);
    BigInteger c3 = c1.multiply(c2).mod(p.getN().pow(2));
    System.out.println("c1*c2 = " + c3);
    System.out.println("D(c1*c2) = " + paillier.dec(s, c3) + " = 128 + 64");

    BigInteger c4 = c1.mod(p.getN().pow(2)).multiply(p.getG().modPow(m2, p.getN().pow(2))).mod(p.getN().pow(2));
    System.out.println("c4 = c1 * g^m2 = " + c4);
    System.out.println("D(c4) = " + paillier.dec(s,c4) + " = 128 + 64");

    byte[] pEnc = p.getEncoded();
    System.out.println("n = " + p.getN());
    System.out.println("g = " + p.getG());

    byte[] b = new byte[4];
    System.arraycopy(pEnc, 0, b, 0, 4);
    int nL = new BigInteger(b).intValue();
    System.arraycopy(pEnc, 4, b, 0, 4);
    int gL =  new BigInteger(b).intValue();
    byte[] pn = new byte[nL];
    byte[] pg = new byte[gL];
    System.arraycopy(pEnc, 8, pn, 0, nL);
    System.arraycopy(pEnc, 8+nL, pg, 0, gL);
    System.out.println("n = " + new BigInteger(pn));
    System.out.println("g = " + new BigInteger(pg));
    
    
  }

}
