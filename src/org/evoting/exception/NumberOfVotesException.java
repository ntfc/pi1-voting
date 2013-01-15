/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.exception;

/**
 *
 * @author nc
 */
public class NumberOfVotesException extends Exception {

  /**
   * Creates a new instance of <code>NumberOfVotesException</code> without detail message.
   */
  public NumberOfVotesException() {
  }


  /**
   * Constructs an instance of <code>NumberOfVotesException</code> with the specified detail message.
   * @param msg the detail message.
   */
  public NumberOfVotesException(String msg) {
    super(msg);
  }
}
