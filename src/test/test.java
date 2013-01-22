/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.numbers.CryptoNumbers;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.interfaces.PaillierPrivateKey;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.cssi.provider.CssiProvider;
import org.evoting.schemes.Ballot;
import org.evoting.zkp.NZKP;

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
    for(int toprepend = strLength-n.length(); toprepend > 0; toprepend--) {
      sb.append('0');
    }
    // append string n
    sb.append(n);
    return sb.toString();
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
    BigInteger e = CryptoNumbers.genRandomZStarN(n, new SecureRandom());
    System.err.println("e = " + e);

    Paillier paillier = new PaillierSimple();
    BigInteger r0 = CryptoNumbers.genRandomZStarN(n, new SecureRandom());
    BigInteger r1 = CryptoNumbers.genRandomZStarN(n, new SecureRandom());
    BigInteger r2 = CryptoNumbers.genRandomZStarN(n, new SecureRandom());

    BigInteger m0 = BigInteger.ONE;
    BigInteger m1 = BigInteger.ZERO;
    BigInteger m2 = BigInteger.ZERO;
    
    BigInteger v0 = paillier.enc(pub, BigInteger.ONE, r0);
    BigInteger v1 = paillier.enc(pub, BigInteger.ZERO, r1);
    BigInteger v2 = paillier.enc(pub, BigInteger.ZERO, r2);
    // interactive ZKP
    int b = 5; // random small integer
    L = 3;
    // k = 0 .. L-1
    Ballot ballot = new Ballot(L); // B = < 1, 0, 0>
    ballot.addVote(0, v0); ballot.addVote(1, v1); ballot.addVote(2, v2);



    // prove that u_k is an n-th power IFF k == i
    // --
    BigInteger tmp00[] = v0.divideAndRemainder(g.pow(m0.intValue()));
    BigInteger u0;
    System.err.println("tmp00 = " + Arrays.toString(tmp00));
    if(tmp00[0].compareTo(BigInteger.ZERO) == 0 || tmp00[0].compareTo(BigInteger.ONE) == 0)
      u0 = tmp00[1].mod(nSquare);
    else
      u0 = tmp00[0].mod(nSquare);
    BigInteger tmp10[] = v1.divideAndRemainder(g.pow(m1.intValue()));
    BigInteger u1;
    System.err.println("tmp10 = " + Arrays.toString(tmp10));
    if(tmp10[0].compareTo(BigInteger.ZERO) == 0 || tmp10[0].compareTo(BigInteger.ONE) == 0)
      u1 = tmp10[1].mod(nSquare);
    else
      u1 = tmp10[0].mod(nSquare);
    // -- i = 2; k = 2 ========>>>> i == k
    // u_i = v_i / g^m_k
    BigInteger u2 = v2.divide(g.modPow(BigInteger.ZERO, nSquare)).mod(nSquare);

    System.err.println("u0 = " + u0);
    System.err.println("u1 = " + u1);
    System.err.println("u2 = " + u2);

    
    BigInteger w = CryptoNumbers.genRandomZStarN(n, new SecureRandom());

    // --- prover generates commitment
    // --
    // -- i = 0; k = 2 ========>>>> i != k

    // -- i = 1; k = 2 ========>>>> i != k

    // -- i = 2; k = 2 ========>>>> i == k
    // a_i = w^n mod n^2 IFF k == i
    BigInteger a2 = w.modPow(n, nSquare);

    // --- verifier chooses a random bit string e_i of length b
    // -- 
    // --
    // -- i = 0; k = 2 ========>>>> i != k

    // -- i = 1; k = 2 ========>>>> i != k

    // -- i = 2; k = 2 ========>>>> i == k
    // e_i of length b IFF k == i
    // 2^b < min(p,q)
    // e_i < 2^b
    BigInteger e2 = CryptoNumbers.genRandomNumber(b, new SecureRandom());

    // --- prover computes z_
    // --
    // -- i = 0; k = 2 ========>>>> i != k

    // -- i = 1; k = 2 ========>>>> i != k

    // -- i = 2; k = 2 ========>>>> i == k
    // z_i = (w * r^e_i) mod n ====> r = random usado para cifrar
    BigInteger z2 = w.mod(n).multiply(r2.modPow(e2, n));


    // --- verification
    // --
    // -- i = 0; k = 2 ========>>>> i != k

    // -- i = 1; k = 2 ========>>>> i != k

    // -- i = 2; k = 2 ========>>>> i == k
    // z_i recebido do prover
    // z_i^n = a_i * u_i^(e_i) mod n^2
    BigInteger z2POWn = a2.mod(nSquare).multiply(u2.modPow(e2, nSquare)).mod(nSquare);
    System.out.println("verification z2 k==i = " + (z2.modPow(n, nSquare).compareTo(z2POWn) == 0));

    

    System.err.println("b = " + b);
    BigInteger b2 = BigInteger.valueOf(2).pow(b);
    System.err.println("2^b = " + b2);

    // -- k != i
    // proves chooses  z_k and random e_k
    // z_k = Z_n^*
    // e_k < 2^b
    BigInteger z0 = CryptoNumbers.genRandomZStarN(n, new SecureRandom());
    BigInteger e0 = CryptoNumbers.genRandomNumber(b, new SecureRandom());
    System.err.println("e0 = " + e0 + ", length = " + e0.bitLength());
    BigInteger z1 = CryptoNumbers.genRandomZStarN(n, new SecureRandom());
    BigInteger e1 = CryptoNumbers.genRandomNumber(b, new SecureRandom());
    System.err.println("e1 = " + e1 + ", length = " + e1.bitLength());

    // commitment
    // prover computes a_k
    // a_k = z_k^n / u_k^(e_k) mod n^2
    BigInteger a0 = z0.modPow(n, nSquare).divide(u0.modPow(e0, nSquare));
    BigInteger a1 = z1.modPow(n, nSquare).divide(u1.modPow(e1, nSquare));


    // verifier challenge
    BigInteger ee = CryptoNumbers.genRandomNumber(b, new SecureRandom());

    // response. prover sends zk and ek

    // verification
    BigInteger z0POWn = a0.multiply(u0.modPow(e0, nSquare));
    BigInteger z1POWn = a1.multiply(u1.modPow(e1, nSquare));
    System.out.println("verification z0 k!=i = " + (z0.modPow(n, nSquare).compareTo(z0POWn) == 0));
    System.out.println("verification z1 k!=i = " + (z1.modPow(n, nSquare).compareTo(z1POWn) == 0));
  }
}
