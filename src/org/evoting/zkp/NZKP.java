/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.zkp;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.cssi.numbers.CryptoNumbers;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.interfaces.PaillierPublicKey;

/**
 * Non-interactive Zero Knowledge Proof
 * <p/>
 * @author nc
 */
public class NZKP {
  BigInteger z, w, b, c;
  public NZKP(PaillierPublicKey pub, BigInteger m) throws PaillierException,
          InvalidKeyException,
          NoSuchAlgorithmException {
    // TODO: validate 0 <= m < N
    
    BigInteger n = pub.getN();
    BigInteger nSquare = n.pow(2);
    BigInteger g = pub.getG();


    System.err.println("n = " + n + "\nn^2 = " + nSquare);

    // r for randomness
    BigInteger r = CryptoNumbers.genRandomZStarN(n, new SecureRandom());

    System.err.println("r = " + r);

    // c = ciphertext
    this.c = new PaillierSimple().enc(pub, m, r);

    System.err.println("c = " + c);

    // random x from Z_n
    BigInteger x = CryptoNumbers.genRandomZN(n, new SecureRandom());

    System.err.println("x = " + x);

    // random u in Z_{n^2]^*
    BigInteger u = CryptoNumbers.genRandomZStarNSquare(nSquare,
                                                       new SecureRandom());

    System.err.println("u = " + u);

    // n+1 = g
    // b = (((n+1)^x mod n^2) * (u^n mod n^2)) mod n^2
    this.b = (g.modPow(x, nSquare).multiply(u.modPow(n, nSquare))).
            mod(nSquare);

    System.err.println("b = " + b);

    // calculate hash
    MessageDigest hashFunction = MessageDigest.getInstance("SHA-1");
    // e = H(c || b)
    hashFunction.update(c.toByteArray());
    BigInteger e = new BigInteger(hashFunction.digest(b.toByteArray()));

    System.err.println("e = " + e);

    // w = x+e*m mod n
    this.w = x.add(e.multiply(m));
    // t = (x+e*m) / n
    BigInteger t = w.divide(n);
    w = w.mod(n);

    System.err.println("w = " + w);
    System.err.println("t = " + t);

    //  (u * 1^e mod n^2) * (g^t mod n^2)
    this.z = ((u.multiply(BigInteger.ONE.modPow(e, nSquare))).mod(nSquare)).multiply(g.modPow(t, nSquare)).mod(nSquare);


  }

  public boolean verify(PaillierPublicKey pub) throws NoSuchAlgorithmException {
    BigInteger n = pub.getN();
    BigInteger nSquare = n.pow(2);
    BigInteger g = pub.getG();
    // calculate hash
    MessageDigest hashFunction = MessageDigest.getInstance("SHA-1");
    // e = H(c || b)
    hashFunction.update(c.toByteArray());
    BigInteger e = new BigInteger(hashFunction.digest(b.toByteArray()));

    // (((n+1)^w mod n^2) * (z^n mod n^2)) mod n^2 == ((b * (c^e mod n^2)) mod n^2)
    BigInteger lhs = (g.modPow(w, nSquare).multiply(z.modPow(n, nSquare))).mod(nSquare);
    BigInteger rhs = b.multiply(c.modPow(e, nSquare)).mod(nSquare);
    return lhs.compareTo(rhs) == 0;
  }
}
