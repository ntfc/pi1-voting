/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.zkp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.cssi.numbers.CryptoNumbers;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.evoting.exception.VariableNotSetException;
import org.utils.ByteUtils;

/**
 *
 * @author nc
 */
public class ZKPValidMProverNonInt extends ZKPValidM {

  public ZKPValidMProverNonInt(BigInteger[] S, PaillierPublicKey pub) throws
    NoSuchAlgorithmException {
    super(S, pub);
    this.hash = MessageDigest.getInstance("SHA-1");
  }

  public Proof generateProof(BigInteger c, BigInteger m, BigInteger rUsedInEnc,
                             BigInteger voterID) throws VariableNotSetException {
    if (pubKey == null) {
      throw new VariableNotSetException("PaillierPublicKey not set");
    }
    for (int j = 0; j < p; j++) {
      if (S[j].compareTo(m) == 0) {
        this.i = j;
      }
    }
    if (this.i < 0) {
      // TODO: throw exception ou continuar com i = random(1..p)??
      throw new IndexOutOfBoundsException("Message m not in S!");
    }
    this.r = rUsedInEnc;
    this.C = c;

    // use non-interactive zkp step1 and step3
    ZKPValidMProverInt niZKP = new ZKPValidMProverInt(S, pubKey);
    // generate stp1
    Proof stp1 = niZKP.generateStep1(c, m, rUsedInEnc);
    // assign u
    this.u = stp1.getProofAsBigIntegerArray();

    // compute h = hash(u, voter_id)
    hash.update(ByteUtils.arrayBigIntegerToByte(u));
    hash.update(voterID.toByteArray());
    byte[] h = hash.digest();
    // create the "challenge" number
    this.ch = new BigInteger(h).mod(n);
    niZKP.receiveStep2(new Proof(ByteUtils.arrayBigIntegerToByte(this.ch)));

    // generate step3
    Proof[] stp3 = niZKP.generateStep3();
    this.e = stp3[0].getProofAsBigIntegerArray();
    this.v = stp3[1].getProofAsBigIntegerArray();
    Proof proof = new InteractiveProof(u, e, v, ch);
    return proof;
  }
}
