/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.numbers.CryptoNumbers;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.interfaces.PaillierPrivateKey;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.cssi.provider.CssiProvider;
import org.evoting.schemes.Ballot;

/**
 *
 * @author nc
 */
public class test {

  public static BigInteger tallyDec = new BigInteger("235");
  public static int base = 25;
  public static int K = 1, L = 3;
  public static List<String> cands = new ArrayList<>();
  private static final Logger LOG = Logger.getLogger(test.class.getName());
  private static int votersWhoVoted = 19;

  public static String results() {
    StringBuilder s = new StringBuilder("Results\n");
    LOG.log(Level.INFO, "tallyDec = {0}", tallyDec.toString());
    // convert tallyDec from base 10 to base defined in the voting scheme
    String tallyBase = tallyDec.toString(base);
    LOG.log(Level.INFO, "tally base {0} = {1}", new Object[]{base, tallyBase});
    // add zeros
    String tallyBaseStr = paddingZeros(tallyBase, L);

    // count non blank votes
    int nonBlank = 0;
    for (int j = (L - 1), index = 0; j >= 0; j--, index++) {
      // count votes for candidate_index
      char nVotesChar = tallyBaseStr.charAt(j);
      // convert from base to base 10
      int nVotes = Integer.parseInt(String.valueOf(nVotesChar), base);
      nonBlank += nVotes;
      // get candidate name from the list of candidates
      String candName = cands.get(index);
      // and append the number of votes in the candidate
      s.append(candName).append(" : ").append(nVotes).append("\n");
      LOG.log(Level.INFO, "votes for candidate {0}(index {1}) = {2}",
              new Object[]{candName,
                index, nVotes});
    }
    int blankVotes = votersWhoVoted - nonBlank;
    s.append("TOTAL: ").append(nonBlank).append(" votos, ");
    s.append(blankVotes).append(" em branco").append("\n");
    return s.toString().trim(); // trim to remove useless \n
  }

  public static String paddingZeros(String n, int strLength) {
    StringBuilder sb = new StringBuilder();

    // append zeros
    for (int toprepend = strLength - n.length(); toprepend > 0; toprepend--) {
      sb.append('0');
    }
    // append string n
    sb.append(n);
    return sb.toString();
  }

  public static BigInteger calcU(PaillierPublicKey pub, BigInteger m, BigInteger c) {
    BigInteger nSquare = pub.getNSquare();
    // u = c/g^m mod n^2 <=> c * (g^m)^-1 mod n^2
    BigInteger u = c.multiply(pub.getG().modPow(m, nSquare).modInverse(nSquare));

    return u.mod(nSquare);
  }

  public static BigInteger[] nthPowerProtocol(PaillierPublicKey pub, BigInteger m) throws PaillierException, InvalidKeyException {
    BigInteger r = CryptoNumbers.genRandomZStarN(pub.getN(), new SecureRandom());
    BigInteger c = new PaillierSimple().enc(pub, m, r);
    return nthPowerProtocol(pub, m, c, r);
  }
  /**
   * 
   * @param pub
   * @param m Plaintext
   */
  public static BigInteger[] nthPowerProtocol(PaillierPublicKey pub, BigInteger m, BigInteger c, BigInteger r) throws PaillierException, InvalidKeyException {
    BigInteger n = pub.getN();
    BigInteger nSquare = pub.getNSquare();


    BigInteger u = calcU(pub, m, c);
    
    if(u.compareTo(r.modPow(n, nSquare)) != 0) {
      System.err.println("U is wrong. Throw exception");
    }
    BigInteger rr = CryptoNumbers.genRandomZN(nSquare, new SecureRandom());
    
    BigInteger a = rr.modPow(n, nSquare);
    // send a to V
    System.err.println("a: " + a + " P --------> V");

    int k = n.bitLength();
    BigInteger e = new BigInteger(k, new SecureRandom());

    // send e to P
    System.err.println("e: " + e + " V --------> P");

    // send z to V
    BigInteger z = rr.multiply(r.modPow(e, nSquare)).mod(nSquare);
    System.err.println("z: " + z + " P --------> V");

    // verification
    BigInteger zPowN = z.modPow(n, nSquare);
    BigInteger toCheck = a.multiply(u.modPow(e, nSquare)).mod(nSquare);

    boolean verification = zPowN.compareTo(toCheck) == 0;
    System.err.println("z^n = a*u^e mod n^2 is " + verification);

    return new BigInteger[]{a, e, z};
  }

  public static BigInteger[] oneOutOfTwoProtocol(PaillierPublicKey pub, BigInteger m) throws PaillierException, InvalidKeyException {
    // init
    BigInteger n = pub.getN();
    BigInteger nSquare = pub.getNSquare();
    BigInteger g = pub.getG();
    Paillier paillier = new PaillierSimple();

    BigInteger r = CryptoNumbers.genRandomZStarN(n, new SecureRandom());
    // vote encrypted
    BigInteger C = paillier.enc(pub, m, r);

    // yes/no plaintext
    BigInteger i1 = BigInteger.ZERO;
    BigInteger i2 = BigInteger.ONE;

    BigInteger u1 = calcU(pub, i1, C);
    BigInteger u2 = calcU(pub, i2, C);


    // starts here
    // r1 in Z_{n^2}^*
    BigInteger r1 = CryptoNumbers.genRandomZN(nSquare, new SecureRandom());
    

    // Invoke M on input n, u2
    /****/
    // u = u2
    // v =

    /****/

    BigInteger[] M = nthPowerProtocol(pub, BigInteger.ONE, C, r);
    BigInteger a2 = M[0];
    BigInteger e2 = M[1];
    BigInteger z2 = M[2];

    BigInteger a1 = r1.modPow(n, nSquare);


    int t = n.bitLength()/2;
    BigInteger s = new BigInteger(t, new SecureRandom());

    BigInteger twoPowT = new BigInteger("2").pow(t);
    BigInteger e1 = s.subtract(e2).mod(twoPowT);
    BigInteger z1 = r1.multiply(r.modPow(e1, nSquare)).mod(nSquare);

    BigInteger sToCheck = e1.add(e2).mod(twoPowT);
    System.err.println("s = e1 + e2 mod 2^t is " + (s.compareTo(sToCheck)==0));

    BigInteger z1ToCheck = a1.multiply(u1.modPow(e1, nSquare)).mod(nSquare);
    BigInteger z1PowN = z1.modPow(n, nSquare);

    System.err.println("z1^n = a1*u1^e1 mod n^2 is " + (z1PowN.compareTo(z1ToCheck) == 0));

    BigInteger z2ToCheck = a2.multiply(u2.modPow(e2, nSquare)).mod(nSquare);
    BigInteger z2PowN = z2.modPow(n, nSquare);

    System.err.println("z2^n = a2*u2^e2 mod n^2 is " + (z2PowN.compareTo(z2ToCheck) == 0));
    return new BigInteger[] {a1, a2, s, e1, e2, z1, z2};
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
    System.err.println("n = " + n);
    BigInteger p = priv.getP();
    BigInteger pMinusOne = p.subtract(BigInteger.ONE);
    System.err.println("p = " + p);
    System.err.println("p-1 = " + pMinusOne);
    BigInteger q = priv.getQ();
    BigInteger qMinusOne = q.subtract(BigInteger.ONE);
    System.err.println("q = " + q);
    System.err.println("q-1 = " + qMinusOne);
    System.err.println("g = " + g);
    System.err.println("phi(n) = " + pMinusOne.multiply(qMinusOne));
    BigInteger pSquare = p.pow(2);
    BigInteger qSquare = q.pow(2);
    BigInteger nSquare = n.pow(2);
    System.err.println("p^2 = " + pSquare);
    System.err.println("q^2 = " + qSquare);
    System.err.println("n^2 = " + nSquare);
    System.err.println("p^2 * q^2 = " + pSquare.multiply(qSquare));


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

    //nthPowerProtocol(pub, m0);
    //nthPowerProtocol(pub, m1);
    //nthPowerProtocol(pub, m2);
    oneOutOfTwoProtocol(pub, m1);

    

  }
}
