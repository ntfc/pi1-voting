/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package test.gui.voters;

import java.net.Socket;
import javax.swing.JOptionPane;

/**
 *
 * @author nc
 */
public class JDialogConnect extends javax.swing.JDialog {
  private Socket cli;
	/** Creates new form JDialogConnect */
	public JDialogConnect(java.awt.Frame parent, boolean modal) {
		super(parent, modal);
		initComponents();
	}

  public Socket showDialog() {
    return cli;

  }
	/** This method is called from within the constructor to
	 * initialize the form.
	 * WARNING: Do NOT modify this code. The content of this method is
	 * always regenerated by the Form Editor.
	 */
	@SuppressWarnings("unchecked")
  // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
  private void initComponents() {
    java.awt.GridBagConstraints gridBagConstraints;

    jPanel1 = new javax.swing.JPanel();
    jLabel2 = new javax.swing.JLabel();
    jButton2 = new javax.swing.JButton();
    jTextPort = new javax.swing.JTextField();

    setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
    getContentPane().setLayout(new java.awt.GridBagLayout());

    jPanel1.setLayout(new java.awt.GridBagLayout());

    jLabel2.setText("Port:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 0;
    jPanel1.add(jLabel2, gridBagConstraints);

    jButton2.setText("Connect");
    jButton2.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        jButton2ActionPerformed(evt);
      }
    });
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 1;
    gridBagConstraints.gridwidth = 2;
    jPanel1.add(jButton2, gridBagConstraints);

    jTextPort.setColumns(5);
    jTextPort.setText("4546");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 0;
    jPanel1.add(jTextPort, gridBagConstraints);

    getContentPane().add(jPanel1, new java.awt.GridBagConstraints());

    pack();
  }// </editor-fold>//GEN-END:initComponents

  private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
    int port = Integer.parseInt(jTextPort.getText());
    try {
      this.cli = new Socket("localhost", port);
      this.dispose();
    }
    catch (Exception ex) {
      JOptionPane.showMessageDialog(this, ex.getMessage());
      ex.printStackTrace();
    }
  }//GEN-LAST:event_jButton2ActionPerformed

  // Variables declaration - do not modify//GEN-BEGIN:variables
  private javax.swing.JButton jButton2;
  private javax.swing.JLabel jLabel2;
  private javax.swing.JPanel jPanel1;
  private javax.swing.JTextField jTextPort;
  // End of variables declaration//GEN-END:variables

}