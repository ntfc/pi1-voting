/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.zkp;

import org.evoting.exception.VariableNotSetException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.cssi.numbers.CryptoNumbers;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.utils.ByteUtils;

/**
 * Non-interactive Zero Knowledge Proof
 * <p/>
 * @author nc
 */
public class NZKP {

  private BigInteger[] u;
  private BigInteger[] e;
  private BigInteger[] v;
  private BigInteger[] S; // set of messages allowed
  private int p;
  private BigInteger ch;
  private BigInteger C;
  private BigInteger peta;
  private PaillierPublicKey pubKey;
  private BigInteger n, nSquare, g;
  private int i; // index of the choosen message

  /**
   * Default constructor, with only 0 and 1 as messages allowed
   */
  public NZKP() {
    this(new BigInteger[]{BigInteger.ZERO, BigInteger.ONE}, null);
  }

  public NZKP(BigInteger[] S) {
    this(S, null);
  }

  public NZKP(BigInteger[] S, PaillierPublicKey pub) {
    this.S = S.clone();
    this.p = this.S.length;
    this.pubKey = pub;
    if (this.pubKey != null) {
      this.n = pubKey.getN();
      this.nSquare = pubKey.getNSquare();
      this.g = pubKey.getG();
    }
    this.e = new BigInteger[p];
    this.u = new BigInteger[p];
    this.v = new BigInteger[p];


  }

  public void setPublicKey(PaillierPublicKey pub) {
    this.pubKey = pub;
    if (this.pubKey != null) {
      this.n = pubKey.getN();
      this.nSquare = pubKey.getNSquare();
      this.g = pubKey.getG();
    }
  }

  /**
   * Step 1 of Non-Interactive ZKP
   *
   * @param c
   * @param rUsedToObtainC
   * @param i
   * @throws VariableNotSetException
   * @return The array to be sent to the verifier
   */
  public byte[] Step1Prover(BigInteger c, int i)
          throws
          VariableNotSetException {
    if (pubKey == null) {
      throw new VariableNotSetException("PaillierPublicKey not set");
    }
    this.i = i;
    this.C = c;
    // generate random peta in Z_n^*
    peta = CryptoNumbers.genRandomZStarN(n, new SecureRandom());

    // generate p-1 values of e
    pickRandomEValues();
    // generate p-1 values of v
    pickRandomVValues();
    // compute p values of u
    computeUValues();

    // byte array to be sent to the Verifier
    return ByteUtils.arrayBigIntegerToByte(u);
  }

  /**
   * Choose a random challenge ch, with t = n.bitLength() / 2 bits
   * <p/>
   * @return The BigInteger as an array
   */
  public byte[] Step2Verifier() {
    // generate a random number, with t = k/2 bits (k = bitLength(n))
    int nBits = n.bitLength() / 2;
    return CryptoNumbers.genRandomNumber(nBits, new SecureRandom()).
            toByteArray();
  }

  /**
   *
   * @param a
   * @return Returns an array with 2 arrays of BigIntegers (both of them as
   * a byte array): v in the first position, and e in the second
   */
  public byte[][] Step3Prover(byte[] a, BigInteger rUsedInEncryption) {
    this.ch = new BigInteger(a);
    BigInteger eeSubtract = ch.subtract(arraySum(e));
    // e_i = ee - sum(e) mod n
    e[i] = eeSubtract.mod(n);

    // Mod(peta * (r^ei) * g^(eeSubstract/ n), n)
    v[i] = peta.multiply(rUsedInEncryption.modPow(e[i], n).multiply(g.modPow(eeSubtract.
            divide(n), n))).mod(n);

    // send v and e
    return new byte[][]{
                         ByteUtils.arrayBigIntegerToByte(v),
                         ByteUtils.arrayBigIntegerToByte(e)
                       };
  }

  public boolean Step4Verifier(byte[][] vAndE) {
    this.v = ByteUtils.byteToArrayBigInteger(vAndE[0]);
    this.e = ByteUtils.byteToArrayBigInteger(vAndE[1]);

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

  /**
   * Randomly picks p-1 values {e_j} such that j != i in Z_n
   */
  private void pickRandomEValues() {
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
  }

  /**
   * Randomly picks p-1 values {v_j} such that j != i in Z_n^*
   */
  private void pickRandomVValues() {
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
  }

  /**
   * Compute u_i = peta^n mod n^2 and set the values for all
   * u_j = v_j^n * (g^m_j / C)^e_j mod n^2 with j != i
   */
  private void computeUValues() {
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
  }

  /**
   * Summation of an array, except the i-th element
   * <p/>
   * @param a
   * @return
   */
  private BigInteger arraySum(BigInteger[] a) {
    BigInteger sum = BigInteger.ZERO;
    for (int j = 0; j < a.length; j++) {
      if (j != i) {
        sum = sum.add(a[i]);
      }
    }
    return sum;
  }
}
