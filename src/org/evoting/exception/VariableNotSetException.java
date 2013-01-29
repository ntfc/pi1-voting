/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.evoting.exception;

/**
 *
 * @author nc
 */
public class VariableNotSetException extends Exception {

  /**
   * Creates a new instance of <code>VariableNotSetException</code> without detail message.
   */
  public VariableNotSetException() {
  }


  /**
   * Constructs an instance of <code>VariableNotSetException</code> with the specified detail message.
   * @param msg the detail message.
   */
  public VariableNotSetException(String msg) {
    super(msg);
  }
}
