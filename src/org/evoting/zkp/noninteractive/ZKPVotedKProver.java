/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.zkp.noninteractive;

import java.math.BigInteger;
import java.security.PublicKey;

/**
 *
 * @author nc
 */
public class ZKPVotedKProver extends ZKPVotedK {

  public ZKPVotedKProver(PublicKey pub) {
    super(pub);
  }

  /**
   * Calculate the product of every r used to encrypt L votes
   * <p>
   * @return 
   */
  public byte[] generateStep1(BigInteger[] rj) {
    super.productR = productModNSquare(rj);
    return productR.toByteArray();    
  }
  
}
