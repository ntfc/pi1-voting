/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test;

import java.util.Random;

/**
 *
 * @author rafaelremondes
 */
public class testClient {

  public static void main(String[] args) {
    int i;
    for (i = 0; i < 14; i++) {
      Random generator = new Random();
      int roll = generator.nextInt(3) + 1;
      Thread t1 = new Thread(new clienteTest(roll));
      t1.start();
    }


  }
}
