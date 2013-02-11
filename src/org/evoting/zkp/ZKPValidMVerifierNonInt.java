/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.zkp;

import java.math.BigInteger;
import org.cssi.paillier.interfaces.PaillierPublicKey;

/**
 *
 * @author nc
 */
public class ZKPValidMVerifierNonInt extends ZKPValidM {

  public ZKPValidMVerifierNonInt(BigInteger[] S, PaillierPublicKey pub) {
    super(S, pub);
  }

  public boolean verify(InteractiveProof p, BigInteger c) {
    this.C = c;
    this.u = p.getUAsBigIntegerArray();
    this.e = p.getEAsBigIntegerArray();
    this.v = p.getVAsBigIntegerArray();
    this.ch = p.getChallengeAsBigInteger();
    
    boolean ret;
    // sum(ej) mod n
    BigInteger ejSum = arraySum(e).mod(n);
    // check that e = sum(ej) mod n
    ret = ch.compareTo(ejSum) == 0;

    for(int j = 0; j < e.length && ret; j++) {
      BigInteger vjN = v[j].modPow(n, nSquare);
      // vjNToCheck = u_j * (C/g^m_j)^e_j mod n^2
      BigInteger vjNToCheck = u[j].multiply(C.multiply(g.pow(S[j].intValue()).modInverse(nSquare)).modPow(e[j], nSquare)).mod(nSquare);
      // verify
      ret = vjN.compareTo(vjNToCheck) == 0;

    }
    return ret;
  }
}
