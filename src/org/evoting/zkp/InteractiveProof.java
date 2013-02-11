/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.zkp;

import java.math.BigInteger;
import org.utils.ByteUtils;


/**
 *
 * @author nc
 */
public class InteractiveProof extends Proof {
  private byte[] ch; // BigInteger
  private byte[] e, v; // arrays of BigInters
  public InteractiveProof(BigInteger[] u, BigInteger[] e, BigInteger[] v, BigInteger ch) {
    super(u);
    this.ch = ch.toByteArray();
    this.e = ByteUtils.arrayBigIntegerToByte(e);
    this.v = ByteUtils.arrayBigIntegerToByte(v);
  }

  public BigInteger getChallengeAsBigInteger() {
    return new BigInteger(ch);
  }

  public BigInteger[] getUAsBigIntegerArray() {
    return super.getProofAsBigIntegerArray();
  }

  public BigInteger[] getEAsBigIntegerArray() {
    return ByteUtils.byteToArrayBigInteger(e);
  }

  public BigInteger[] getVAsBigIntegerArray() {
    return ByteUtils.byteToArrayBigInteger(v);
  }
}
