/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.zkp.noninteractive;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.List;
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
  public byte[] generateStep2(List<BigInteger> cj) {
    super.productC = productModNSquare(cj);
    return productC.toByteArray();
  }

  public boolean verify() throws PaillierException, InvalidKeyException {
    int kAux = K;
    // NOTE: neste momento, prova-se que se votou entre 0 e K candidatos
    while(kAux >= 0) {
      // E(K, productR) == productC ==> tudo ok, votou em kAux candidatos
      BigInteger cc = new PaillierSimple().enc(pubKey, BigInteger.valueOf(kAux), productR.mod(n));
      if(cc.compareTo(productC) == 0) {
        return true;
      }
      kAux--;
    }
    // E(K, productR) == productC ==> tudo ok, votou em K candidatos
    return false;
  }

}
