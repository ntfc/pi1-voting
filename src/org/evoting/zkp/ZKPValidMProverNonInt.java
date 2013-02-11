/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.zkp;

import org.evoting.schemes.proofs.InteractiveProof;
import org.evoting.schemes.proofs.NonInteractiveProof;
import org.evoting.schemes.proofs.Proof;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.cssi.paillier.interfaces.PaillierPublicKey;
import org.evoting.exception.VariableNotSetException;
import org.utils.ByteUtils;

/**
 * Prove that a message lies in a given set of messages, non-interactive version
 *
 * @author nc
 */
public class ZKPValidMProverNonInt extends ZKPValidM {

  public ZKPValidMProverNonInt(BigInteger[] S, PaillierPublicKey pub) throws
    NoSuchAlgorithmException {
    super(S, pub);
    this.hash = MessageDigest.getInstance("SHA-1");
  }

  public NonInteractiveProof generateProof(BigInteger c, BigInteger m,
                                           BigInteger rUsedInEnc,
                                           BigInteger voterID) throws
    VariableNotSetException {
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
    ZKPValidMProverInt intZKP = new ZKPValidMProverInt(S, pubKey);
    // generate stp1
    Proof stp1 = intZKP.generateStep1(c, m, rUsedInEnc);
    // assign u
    this.u = ByteUtils.byteToArrayBigInteger(stp1.getProofEncoded());

    // compute h = hash(u, voter_id)
    hash.update(ByteUtils.arrayBigIntegerToByte(u));
    hash.update(voterID.toByteArray());
    byte[] h = hash.digest();
    // create the "challenge" number
    this.ch = new BigInteger(h).mod(n);
    intZKP.receiveStep2(
      new InteractiveProof(ByteUtils.arrayBigIntegerToByte(ch)));

    // generate step3
    Proof[] stp3 = intZKP.generateStep3();
    this.e = ByteUtils.byteToArrayBigInteger(stp3[0].getProofEncoded());
    this.v = ByteUtils.byteToArrayBigInteger(stp3[1].getProofEncoded());
    NonInteractiveProof proof = new NonInteractiveProof(u, ch, e, v);
    return proof;
  }
}
