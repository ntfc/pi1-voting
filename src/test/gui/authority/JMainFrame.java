/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package test.gui.authority;

import java.io.IOException;
import org.evoting.authority.VotingServer;

/**
 *
 * @author nc
 */
public class JMainFrame extends javax.swing.JFrame {
  private VotingServer tServer;

	/** Creates new form JMainFrame */
	public JMainFrame() {
		initComponents();
	}

  private void startServer(int port, int cands, int base, int voters) {
    /*tServer = new VotingServer(port, cands, base, voters);
    tServer.start();
    System.out.println("server running @ " + port);*/
  }

  private void stopServer() throws IOException {
    /*this.tServer.stopServer();
    System.out.println("server stopped");*/
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

    jPanelVotingProps = new javax.swing.JPanel();
    javax.swing.JLabel jLabel1 = new javax.swing.JLabel();
    javax.swing.JLabel jLabel2 = new javax.swing.JLabel();
    javax.swing.JLabel jLabel3 = new javax.swing.JLabel();
    javax.swing.JLabel jLabel4 = new javax.swing.JLabel();
    jTextFieldPort = new javax.swing.JTextField();
    jSpinnerNrCands = new javax.swing.JSpinner();
    jSpinnerBase = new javax.swing.JSpinner();
    jSpinnerNrVoters = new javax.swing.JSpinner();
    jButtonStartStop = new javax.swing.JButton();
    jLabelServerStatus = new javax.swing.JLabel();

    setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
    getContentPane().setLayout(new java.awt.GridBagLayout());

    jPanelVotingProps.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createTitledBorder(""), "Voting Properties"));
    jPanelVotingProps.setLayout(new java.awt.GridBagLayout());

    jLabel1.setText("Server port:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_END;
    jPanelVotingProps.add(jLabel1, gridBagConstraints);

    jLabel2.setText("Nr. candidates:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 1;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_END;
    jPanelVotingProps.add(jLabel2, gridBagConstraints);

    jLabel3.setText("Nr. voters:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 3;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_END;
    jPanelVotingProps.add(jLabel3, gridBagConstraints);

    jLabel4.setText("Base:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 2;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_END;
    jPanelVotingProps.add(jLabel4, gridBagConstraints);

    jTextFieldPort.setEditable(false);
    jTextFieldPort.setColumns(4);
    jPanelVotingProps.add(jTextFieldPort, new java.awt.GridBagConstraints());

    jSpinnerNrCands.setModel(new javax.swing.SpinnerNumberModel(1, 1, 10, 1));
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 1;
    jPanelVotingProps.add(jSpinnerNrCands, gridBagConstraints);

    jSpinnerBase.setModel(new javax.swing.SpinnerNumberModel(2, 2, 20, 1));
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 2;
    jPanelVotingProps.add(jSpinnerBase, gridBagConstraints);

    jSpinnerNrVoters.setModel(new javax.swing.SpinnerNumberModel(5, 5, 100, 1));
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 3;
    jPanelVotingProps.add(jSpinnerNrVoters, gridBagConstraints);

    jButtonStartStop.setText("Start Server");
    jButtonStartStop.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        jButtonStartStopActionPerformed(evt);
      }
    });
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 4;
    jPanelVotingProps.add(jButtonStartStop, gridBagConstraints);

    jLabelServerStatus.setText("jLabel5");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 4;
    jPanelVotingProps.add(jLabelServerStatus, gridBagConstraints);

    getContentPane().add(jPanelVotingProps, new java.awt.GridBagConstraints());

    pack();
  }// </editor-fold>//GEN-END:initComponents

  private void jButtonStartStopActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonStartStopActionPerformed
    
    /*if(tServer == null || !tServer.isRunning()) {
      int port = 4567;
      int base = (int) jSpinnerBase.getValue();
      int cands = (int) jSpinnerNrCands.getValue();
      int voters = (int) jSpinnerNrVoters.getValue();
      this.startServer(port, cands, base, voters);
      jButtonStartStop.setText("Stop Server");
    }
    else {
      try {
        this.stopServer();
        jButtonStartStop.setText("Start Server");
      }
      catch (IOException ex) {
        System.err.println("Error stoping server.");
      }
    }

    jLabelServerStatus.setText(Boolean.toString(tServer.isRunning()));*/
  }//GEN-LAST:event_jButtonStartStopActionPerformed

	/**
	 * @param args the command line arguments
	 */
	public static void main(String args[]) {
		

		/* Create and display the form */
		java.awt.EventQueue.invokeLater(new Runnable() {
			public void run() {
				new JMainFrame().setVisible(true);
			}
		});
	}

  // Variables declaration - do not modify//GEN-BEGIN:variables
  private javax.swing.JButton jButtonStartStop;
  private javax.swing.JLabel jLabelServerStatus;
  private javax.swing.JPanel jPanelVotingProps;
  private javax.swing.JSpinner jSpinnerBase;
  private javax.swing.JSpinner jSpinnerNrCands;
  private javax.swing.JSpinner jSpinnerNrVoters;
  private javax.swing.JTextField jTextFieldPort;
  // End of variables declaration//GEN-END:variables

}
