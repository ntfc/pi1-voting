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
public class InteractiveProof extends Proof {

  public InteractiveProof(byte[] u) {
    super(u);
  }

  public InteractiveProof(BigInteger[] u) {
    super(u);
  }

  @Override
  public byte[] getProofEncoded() {
    return ByteUtils.arrayBigIntegerToByte(u);
  }
}
