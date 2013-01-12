/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.exception;

/**
 *
 * @author nc
 */
public class VotingSchemeException extends Exception {

  /**
   * Creates a new instance of <code>VotingSchemeException</code> without detail message.
   */
  public VotingSchemeException() {
  }


  /**
   * Constructs an instance of <code>VotingSchemeException</code> with the specified detail message.
   * @param msg the detail message.
   */
  public VotingSchemeException(String msg) {
    super(msg);
  }
}
