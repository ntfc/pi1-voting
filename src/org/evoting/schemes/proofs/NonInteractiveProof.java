/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.schemes.proofs;

import java.math.BigInteger;
import org.utils.ByteUtils;

/**
 *
 * @author nc
 */
public class NonInteractiveProof extends Proof {

  private BigInteger ch; // challenge BigInteger
  private BigInteger[] e, v; // arrays of BigInters

  public NonInteractiveProof(BigInteger[] u, BigInteger ch, BigInteger[] e,
                             BigInteger[] v) {
    super(u);
    this.ch = ch;
    this.e = e;
    this.v = v;
  }

  public NonInteractiveProof(byte[][] p) {
    super(ByteUtils.byteToArrayBigInteger(p[0]));
    this.ch = ByteUtils.byteToArrayBigInteger(p[1])[0];
    this.e = ByteUtils.byteToArrayBigInteger(p[2]);
    this.v = ByteUtils.byteToArrayBigInteger(p[3]);
  }

  @Override
  public byte[] getProofEncoded() {
    byte[] uEnc = ByteUtils.arrayBigIntegerToByte(u);
    byte[] chEnc = ByteUtils.arrayBigIntegerToByte(ch);
    byte[] eEnc = ByteUtils.arrayBigIntegerToByte(e);
    byte[] vEnc = ByteUtils.arrayBigIntegerToByte(v);
    return ByteUtils.arrayBytetoByte(uEnc, chEnc, eEnc, vEnc);
  }
}
