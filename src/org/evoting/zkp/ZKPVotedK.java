/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.zkp;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;
import org.cssi.paillier.interfaces.PaillierPublicKey;

/**
 * Zero-knowledge proof to show that one voter indeed voted for exactly K
 * candidates
 *
 * @author nc
 */
/*
 * public
 */ abstract class ZKPVotedK {

  protected PublicKey pubKey;
  protected int K;
  protected BigInteger n, nSquare;
  protected BigInteger productR; // product of all r's used to encrypt mod n^2
  protected BigInteger productC; // product of all ciphertexts mod n^2

  // used by the verifier
  public ZKPVotedK(PublicKey pubKey, int k) {
    this.setPubKey(pubKey);
    this.K = k;
  }

  // used by the prover
  public ZKPVotedK(PublicKey pubKey) {
    this.setPubKey(pubKey);
  }

  private void setPubKey(PublicKey pubKey) {
    this.pubKey = pubKey;
    this.n = ((PaillierPublicKey) pubKey).getN();
    this.nSquare = ((PaillierPublicKey) pubKey).getNSquare();
  }

  /**
   * Calcute a product of
   * <code>r</code> BigInteger's, modulo
   * <code>nSquare</code>.
   * <p/>
   * @param r
   * @return
   */
  protected final BigInteger productMod(BigInteger m, BigInteger... r) {
    if (r.length < 1) {
      return BigInteger.ZERO;
    }

    BigInteger ret = BigInteger.ONE;
    for (BigInteger a : r) {
      ret = ret.multiply(a).mod(m);
    }
    return ret.mod(m);
  }

  protected final BigInteger productModNSquare(BigInteger m, List<BigInteger> n) {
    if (n.size() < 1) {
      return BigInteger.ZERO;
    }

    BigInteger ret = BigInteger.ONE;
    for (BigInteger a : n) {
      ret = ret.multiply(a).mod(m);
    }
    return ret.mod(m);
  }
}
