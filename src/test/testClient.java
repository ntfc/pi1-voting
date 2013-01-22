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
    for (i = 0; i < 300; i++) {
      Random generator = new Random();
      int max = 5;

      int roll = generator.nextInt(max) + 1;
      Thread t1 = new Thread(new clienteTest(roll, roll));
      //Thread t1 = new Thread(new clienteTest(generator.nextInt(max) + 1, generator.nextInt(max) + 1));
      t1.start();
    }


  }
}
