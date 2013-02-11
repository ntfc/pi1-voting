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
public abstract class Proof {

  protected BigInteger[] u;

  public Proof(byte[] u) {
    this.u = ByteUtils.byteToArrayBigInteger(u);
  }

  public Proof(BigInteger[] u) {
    this.u = u;
  }

  /**
   * Returns a byte[] representation of the proof.
   * <p>
   * All <b>Non-Interactive</b> proofs must be of the following form:
   * || u | ch | e | v ||. <br>
   * All <b>Interactive</b> must only contain one step at each time, ie, this
   * outputs only one of the following: u, ch, e or v.
   * <p/>
   * @return
   */
  public abstract byte[] getProofEncoded();
}
