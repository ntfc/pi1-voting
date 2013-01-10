/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.authority;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cssi.provider.CssiProvider;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.interfaces.PaillierPrivateKey;
import org.cssi.paillier.interfaces.PaillierPublicKey;


/**
 *
 * @author miltonnunes52
 */
public class Votes {
    private ArrayList<BigInteger> votes;
    private BigInteger results;
    private  PaillierPrivateKey pK;
    
    
    public Votes(ArrayList<BigInteger> nVotes){
        this.votes = nVotes;
        this.pK = null;
    }
    
    public Votes(){
        this.votes = new ArrayList<BigInteger>();
        this.pK = null;
    }
    
    public void add(BigInteger vote){
        votes.add(vote);
    }
    
    public void setPrivateKey(PaillierPrivateKey s){
        pK = s;
    }
    
    //contagem dos votos
    public BigInteger tallying() throws PaillierException, InvalidKeyException{
        BigInteger result;
        BigInteger t;
        BigInteger mult = BigInteger.valueOf(1);
        for(BigInteger v :votes){
            mult = mult.multiply(v);
        }
        t = mult.mod(pK.getN().pow(2));
        
        Paillier paillier = new PaillierSimple();
        result = paillier.dec(pK, t);
    
        return result;
    }
    
    //apresentar resultados
    public void printResults(int nCands) throws PaillierException, InvalidKeyException{
        String result = tallying().toString();
        int index = 1;
        System.out.println(result);
        System.out.println("Resultados:\n");
        for(int i = (nCands-1); i >= 0 ;i--){          
            System.out.println("Opção " + index + " : " + result.charAt(i));
            index++;
        }
        
    }
    
    public int nVotes(){
        return votes.size();
    }
    
}
