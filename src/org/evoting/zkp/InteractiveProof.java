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
  
  public InteractiveProof(BigInteger[] u, BigInteger ch, BigInteger[] e, BigInteger[] v) {
    super(u);
    this.ch = ch.toByteArray();
    this.e = ByteUtils.arrayBigIntegerToByte(e);
    this.v = ByteUtils.arrayBigIntegerToByte(v);
  }
  /**
   * Consctructs a new non-interactive proof from a given byte array of byte[]
   * <p>
   * The array must be of the following form (all fields as encoded array's of
   * BigInteger):<br>
   * || u | ch | e | v ||
   * @param proof
   */
  public InteractiveProof(byte[][] proof) {
    super(proof[0]);
    ch = proof[1];
    e = proof[2];
    v = proof[3];


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

  @Override
  public byte[] getProofAsByteArray() {
    return ByteUtils.arrayBytetoByte(proof, ch, e, v);
  }


}
