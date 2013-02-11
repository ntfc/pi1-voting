/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.zkp.interactive;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.cssi.numbers.CryptoNumbers;
import org.cssi.paillier.interfaces.PaillierPublicKey;

/**
 * Non-interactive Zero Knowledge Proof
 * <p/>
 * @author nc
 */
/*public*/ abstract class ZKPSetOfMessages {

  protected BigInteger[] u;
  protected BigInteger[] e;
  protected BigInteger[] v;
  protected BigInteger[] S; // set of messages allowed
  protected int p;
  protected BigInteger ch;
  protected BigInteger C;
  protected BigInteger peta;
  protected PaillierPublicKey pubKey;
  protected BigInteger n, nSquare, g;
  protected int i; // index of the choosen message
  protected BigInteger r; // r used to encrypt m_i into C

  /**
   * <b>Used only by the verifier</b>
   * @param S
   * @param pub
   * @param c
   */
  public ZKPSetOfMessages(BigInteger[] S, PaillierPublicKey pub, BigInteger c) {
    this(S, pub, -1, c, null);
  }
  
  /**
   * <b>Used only by the prover</b>
   * @param S
   * @param pub
   * @param i
   * @param c
   * @param rUsedInEncryption
   */
  public ZKPSetOfMessages(BigInteger[] S, PaillierPublicKey pub, int i, BigInteger c, BigInteger rUsedInEncryption) {
    this.S = S.clone();
    this.p = this.S.length;
    this.pubKey = pub;
    if (this.pubKey != null) {
      this.n = pubKey.getN();
      this.nSquare = pubKey.getNSquare();
      this.g = pubKey.getG();
    }
    this.i = i;
    this.C = c;
    this.r = rUsedInEncryption;
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
   * Randomly picks p-1 values {e_j} such that j != i in Z_n
   */
  protected void pickRandomEValues() {
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
  protected void pickRandomVValues() {
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
  protected void computeUValues() {
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
  protected BigInteger arraySum(BigInteger[] a) {
    BigInteger sum = BigInteger.ZERO;
    for (int j = 0; j < a.length; j++) {
      if (j != i) {
        sum = sum.add(a[j]);
      }
    } 
    return sum;
  }

public void setCh(byte[] b) { this.ch = new BigInteger(b); }
}
