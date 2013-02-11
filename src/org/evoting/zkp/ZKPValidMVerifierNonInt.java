/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.zkp;

import org.evoting.schemes.proofs.NonInteractiveProof;
import java.math.BigInteger;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.utils.ByteUtils;

/**
 * Verify that a messages lies in a set of messages, non-interactive version
 *
 * @author nc
 */
public class ZKPValidMVerifierNonInt extends ZKPValidM {

  public ZKPValidMVerifierNonInt(BigInteger[] S, PaillierPublicKey pub) {
    super(S, pub);
  }

  public boolean verify(NonInteractiveProof p, BigInteger c) {
    this.C = c;
    byte[] pEnc = p.getProofEncoded();
    byte[][] pEncArrays = ByteUtils.byteToArrayByte(pEnc);
    this.u = ByteUtils.byteToArrayBigInteger(pEncArrays[0]);
    this.ch = ByteUtils.byteToArrayBigInteger(pEncArrays[1])[0];
    this.e = ByteUtils.byteToArrayBigInteger(pEncArrays[2]);
    this.v = ByteUtils.byteToArrayBigInteger(pEncArrays[3]);


    boolean ret;
    // sum(ej) mod n
    BigInteger ejSum = arraySum(e).mod(n);
    // check that e = sum(ej) mod n
    ret = ch.compareTo(ejSum) == 0;

    for (int j = 0; j < e.length && ret; j++) {
      BigInteger vjN = v[j].modPow(n, nSquare);
      // vjNToCheck = u_j * (C/g^m_j)^e_j mod n^2
      BigInteger vjNToCheck = u[j].multiply(C.multiply(g.pow(S[j].intValue()).
        modInverse(nSquare)).modPow(e[j], nSquare)).mod(nSquare);
      // verify
      ret = vjN.compareTo(vjNToCheck) == 0;

    }
    return ret;
  }
}
