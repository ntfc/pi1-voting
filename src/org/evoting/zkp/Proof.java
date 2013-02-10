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
public class Proof {
  // byte[] holds an array of BigInteger[]
  private byte[] proof;
  
  public Proof(byte[] p) {
    this.proof = p;
  }
  public Proof(BigInteger[] b) {
    this.proof = ByteUtils.arrayBigIntegerToByte(b);
  }
  
  public BigInteger[] getProofAsBigIntegerArray() {
    return ByteUtils.byteToArrayBigInteger(proof);
  }
  
  public byte[] getProofAsByteArray() {
    return proof;
  }



}
