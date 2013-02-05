/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import org.cssi.numbers.CryptoNumbers;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.interfaces.PaillierPrivateKey;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.cssi.provider.CssiProvider;
import org.evoting.schemes.Ballot;

/**
 *
 * @author nc
 */
public class Test {

  public static BigInteger tallyDec = new BigInteger("235");
  public static int base = 25;
  public static int K = 1, L = 3;
  public static List<String> cands = new ArrayList<>();
  private static final Logger LOG = Logger.getLogger(Test.class.getName());
  private static int votersWhoVoted = 19;
  private static BigInteger[] S = new BigInteger[]{BigInteger.ZERO,
    BigInteger.ONE};

  // TODO: meter isto mais bonito, numa classe ZKP no provider
  // TODO: also, nao usar [][]
  // Prover
  private static BigInteger[][] NZKP_step1(PaillierPublicKey pub, int i,
                                           BigInteger C, BigInteger r) {
    // length of the set of messages
    int p = S.length;
    BigInteger e[] = new BigInteger[p];
    BigInteger v[] = new BigInteger[p];
    BigInteger u[] = new BigInteger[p];
    BigInteger n = pub.getN();
    BigInteger nSquare = pub.getNSquare();
    BigInteger g = pub.getG();

    // randomly pick peta
    BigInteger peta = CryptoNumbers.genRandomZStarN(n, new SecureRandom());

    // randomly pick p-1 values e_j (j != i)
    for (int j = 0; j < p; j++) {
      // in all positions different from i, e_j = random Z_n
      if (j != i) {
        e[j] = CryptoNumbers.genRandomZN(n, new SecureRandom());
      }
      else {
        // e_i is 0, for now
        e[i] = BigInteger.ZERO;
      }
    }

    // randomly pick p-1 values v_j (j != i)
    for (int j = 0; j < p; j++) {
      // in all positions different from i, v_j = random Z_n^*
      if (j != i) {
        v[j] = CryptoNumbers.genRandomZStarN(n, new SecureRandom());
      }
      else {
        // v_i is 0, for now
        v[i] = BigInteger.ZERO;
      }
    }

    for (int j = 0; j < p; j++) {
      if (j != i) {
        // u_j = v_j^n * (g^m_j / C)^e_j mod n^2
        BigInteger tmp1 = g.pow(S[j].intValue()).multiply(C.modInverse(nSquare));
        u[j] = v[j].modPow(n, nSquare).multiply(tmp1.modPow(e[j], nSquare)).mod(
                nSquare);
      }
      else {
        // compute ui = peta^n mod n^2
        u[i] = peta.modPow(n, nSquare);
      }
    }

    return new BigInteger[][]{new BigInteger[]{peta}, e, v, u};
  }

  // Verifier
  public static BigInteger NZKP_step2(PaillierPublicKey pub) {
    // generate a random number, with t = k/2 bits (k = bitLength(n))
    int nBits = pub.getN().bitLength() / 2;
    return CryptoNumbers.genRandomNumber(nBits, new SecureRandom());
  }

  // Prover
  public static void NZKP_step3(PaillierPublicKey pub, int i, BigInteger r, BigInteger ch, BigInteger peta,
                                      BigInteger[] e, BigInteger[] v) {
    BigInteger n = pub.getN();
    BigInteger g = pub.getG();

    // i dont need to return the arrays!

    BigInteger eeSubtract = ch.subtract(arraySum(e));
    // e_i = ee - sum(e) mod n
    e[i] = eeSubtract.mod(n);

    // Mod(peta * (r^ei) * g^(eeSubstract/ n), n)
    v[i] = peta.multiply(r.modPow(e[i], n).multiply(g.modPow(eeSubtract.divide(n), n))).mod(n);
  }

  // verifier
  public static boolean NZKP_step4(PaillierPublicKey pub, BigInteger ch, BigInteger[] e, BigInteger v[], BigInteger[] u, BigInteger C) {
    BigInteger n = pub.getN();
    BigInteger nSquare = pub.getNSquare();
    BigInteger g = pub.getG();
    boolean ret;
    // sum(ej) mod n
    BigInteger ejSum = arraySum(e).mod(n);
    // check that e = sum(ej) mod n
    ret = ch.compareTo(ejSum) == 0;

    for(int j = 0; j < e.length && ret; j++) {
      BigInteger vjN = v[j].modPow(n, nSquare);
      // vjNToCheck = u_j * (C/g^m_j)^e_j mod n^2
      BigInteger vjNToCheck = u[j].multiply(C.multiply(g.pow(S[j].intValue()).modInverse(nSquare)).modPow(e[j], nSquare)).mod(nSquare);
      // verification
      ret = vjN.compareTo(vjNToCheck) == 0;

    }
    return ret;
  }

  private static BigInteger arraySum(BigInteger[] a) {
    BigInteger res = BigInteger.ZERO;
    for(BigInteger b : a)
      res = res.add(b);
    return res;
  }

  public static void main(String[] args) throws Exception {
    cands.add("A");
    cands.add("B");
    cands.add("C");
    cands.add("D");
    cands.add("E");
//    String s = results();
//    System.out.println(s);
    Security.addProvider(new CssiProvider());
    // Generate keys
    KeyPairGenerator kGen = KeyPairGenerator.getInstance("Paillier", "CSSI");
    kGen.initialize(12);
    KeyPair kP = kGen.generateKeyPair();

    PaillierPublicKey pub = (PaillierPublicKey) kP.getPublic();
    PaillierPrivateKey priv = (PaillierPrivateKey) kP.getPrivate();
    BigInteger n = pub.getN();
    BigInteger g = pub.getG();
    BigInteger nSquare = pub.getNSquare();

    Paillier paillier = new PaillierSimple();
    BigInteger r0 = CryptoNumbers.genRandomZStarN(n, new SecureRandom());
    BigInteger r1 = CryptoNumbers.genRandomZStarN(n, new SecureRandom());
    BigInteger r2 = CryptoNumbers.genRandomZStarN(n, new SecureRandom());

    BigInteger m0 = BigInteger.ONE;
    BigInteger m1 = BigInteger.ZERO;
    BigInteger m2 = BigInteger.ZERO;

    BigInteger c0 = paillier.enc(pub, m0, r0);
    BigInteger c1 = paillier.enc(pub, m1, r1);
    BigInteger c2 = paillier.enc(pub, m2, r2);
    // interactive ZKP
    int b = 5; // random small integer
    L = 3;
    // k = 0 .. L-1
    Ballot ballot = new Ballot(L); // B = < 1, 0, 0>
    ballot.addVote(0, c0);
    ballot.addVote(1, c1);
    ballot.addVote(2, c2);

    // step 1
    BigInteger[][] step1_1 = NZKP_step1(pub, 1, c0, r0);
    BigInteger peta1 = step1_1[0][0];
    BigInteger[] e1 = step1_1[1];
    BigInteger[] v1 = step1_1[2];
    BigInteger[] u1 = step1_1[3];
    BigInteger ee1 = NZKP_step2(pub);
    NZKP_step3(pub, 1, r0, ee1, peta1, e1, v1);
    System.out.println(NZKP_step4(pub, ee1, e1, v1, u1, c0));

    BigInteger[][] step1_2 = NZKP_step1(pub, 0, c1, r1);
    BigInteger peta2 = step1_2[0][0];
    BigInteger[] e2 = step1_2[1];
    BigInteger[] v2 = step1_2[2];
    BigInteger[] u2 = step1_2[3];
    BigInteger ee2 = NZKP_step2(pub);
    NZKP_step3(pub, 0, r1, ee2, peta2, e2, v2);
    System.out.println(NZKP_step4(pub, ee2, e2, v2, u2, c1));

    BigInteger[][] step1_3 = NZKP_step1(pub, 0, c2, r2);
    BigInteger peta3 = step1_3[0][0];
    BigInteger[] e3 = step1_3[1];
    BigInteger[] v3 = step1_3[2];
    BigInteger[] u3 = step1_3[3];
    BigInteger ee3 = NZKP_step2(pub);
    NZKP_step3(pub, 0, r2, ee3, peta3, e3, v3);
    System.out.println(NZKP_step4(pub, ee3, e3, v3, u3, c2));





  }
}
