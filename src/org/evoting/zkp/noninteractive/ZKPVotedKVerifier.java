/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.zkp.noninteractive;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;

/**
 *
 * @author nc
 */
public class ZKPVotedKVerifier extends ZKPVotedK {
  
  public ZKPVotedKVerifier(PublicKey pub, int K) {
    super(pub, K);
  }

  public void receiveStep1(byte[] data) {
    BigInteger rj = new BigInteger(data);
    super.productR = rj;
  }

  /**
   * Calculate the product of all ciphertexts
   * @param cj
   * @return
   */
  public byte[] generateStep2(BigInteger[] cj) {
    super.productC = productModNSquare(cj);
    return productC.toByteArray();
  }

  public boolean verify() throws PaillierException, InvalidKeyException {
    BigInteger c2 = new PaillierSimple().enc(pubKey, BigInteger.valueOf(K), productR.mod(n));
    // E(K, productR) == productC ==> tudo ok, votou em K candidatos
    return c2.compareTo(productC) == 0;
  }

}
