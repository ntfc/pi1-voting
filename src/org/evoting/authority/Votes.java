/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.authority;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.paillier.interfaces.PaillierPrivateKey;


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
        String result = String.format("%0"+nCands+"d", tallying());
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
