/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.evoting.schemes;

import java.math.BigInteger;
import java.util.Comparator;
import java.util.Map;

/**
 *
 * @author rafaelremondes
 */
 public class valueComparator implements Comparator<Integer> {

    private Map<Integer, BigInteger> base;

    public valueComparator(Map<Integer, BigInteger> base) {
      this.base = base;
    }

    // Note: this comparator imposes orderings that are inconsistent with equals.
    public int compare(Integer a, Integer b) {
      if (base.get(a).intValue() >= base.get(b).intValue()) {
        return -1;
      } else {
        return 1;
      } // returning 0 would merge keys
    }
  }
