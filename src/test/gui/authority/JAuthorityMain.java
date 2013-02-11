/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test.gui.authority;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import javax.swing.SwingWorker;
import javax.swing.UnsupportedLookAndFeelException;
import org.cssi.paillier.cipher.Paillier;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.provider.CssiProvider;
import org.evoting.authority.VotingServer;
import org.evoting.exception.VotingSchemeException;
import org.evoting.schemes.Voting;
import test.gui.CommonMethods;

/**
 *
 */
public class JAuthorityMain extends javax.swing.JFrame {
  private VotingServer server;
  private PrivateKey privKey;
  private static final Logger LOG = Logger.getLogger(JAuthorityMain.class.getName());
  /**
   * Creates new form JAuthorityMain
   */
  public JAuthorityMain() {
    initComponents();
    setLocationRelativeTo(null);
  }

  /**
   * This method is called from within the constructor to initialize the form.
   * WARNING: Do NOT modify this code. The content of this method is always
   * regenerated by the Form Editor.
   */
  @SuppressWarnings("unchecked")
  // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
  private void initComponents() {
    java.awt.GridBagConstraints gridBagConstraints;

    jPanel1 = new javax.swing.JPanel();
    jLabel1 = new javax.swing.JLabel();
    jSpinnerVoters = new javax.swing.JSpinner();
    jScrollPane1 = new javax.swing.JScrollPane();
    jTextPaneCands = new javax.swing.JTextPane();
    jLabel5 = new javax.swing.JLabel();
    jTextFieldPort = new javax.swing.JTextField();
    jLabel6 = new javax.swing.JLabel();
    jSpinnerTimeout = new javax.swing.JSpinner();
    jLabel7 = new javax.swing.JLabel();
    jPanel2 = new javax.swing.JPanel();
    jButtonClose = new javax.swing.JButton();
    jButtonStart = new javax.swing.JButton();
    jLabel4 = new javax.swing.JLabel();
    jSpinnerK = new javax.swing.JSpinner();
    jLabel2 = new javax.swing.JLabel();
    jLabel3 = new javax.swing.JLabel();

    setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
    setTitle("eVoting");
    setMinimumSize(new java.awt.Dimension(405, 350));
    setPreferredSize(new java.awt.Dimension(405, 350));
    getContentPane().setLayout(new java.awt.GridBagLayout());

    jPanel1.setLayout(new java.awt.GridBagLayout());

    jLabel1.setText("Nr. voters:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 0;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
    jPanel1.add(jLabel1, gridBagConstraints);

    jSpinnerVoters.setModel(new javax.swing.SpinnerNumberModel(Integer.valueOf(1), Integer.valueOf(1), null, Integer.valueOf(10)));
    jSpinnerVoters.setMinimumSize(new java.awt.Dimension(53, 20));
    jSpinnerVoters.setPreferredSize(new java.awt.Dimension(45, 25));
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 0;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
    jPanel1.add(jSpinnerVoters, gridBagConstraints);

    jScrollPane1.setMinimumSize(new java.awt.Dimension(150, 100));
    jScrollPane1.setPreferredSize(new java.awt.Dimension(150, 100));
    jScrollPane1.setViewportView(jTextPaneCands);

    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 2;
    gridBagConstraints.gridheight = 2;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
    jPanel1.add(jScrollPane1, gridBagConstraints);

    jLabel5.setText("Server port:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 4;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
    jPanel1.add(jLabel5, gridBagConstraints);

    jTextFieldPort.setColumns(5);
    jTextFieldPort.setText("4546");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 4;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
    jPanel1.add(jTextFieldPort, gridBagConstraints);

    jLabel6.setText("Timeout (min):");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 5;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
    jPanel1.add(jLabel6, gridBagConstraints);

    jSpinnerTimeout.setModel(new javax.swing.SpinnerNumberModel(Double.valueOf(1.0d), Double.valueOf(0.1d), null, Double.valueOf(1.0d)));
    jSpinnerTimeout.setPreferredSize(new java.awt.Dimension(55, 25));
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 5;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
    jPanel1.add(jSpinnerTimeout, gridBagConstraints);

    jLabel7.setText("Candidates:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 2;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
    jPanel1.add(jLabel7, gridBagConstraints);

    jPanel2.setLayout(new java.awt.GridBagLayout());

    jButtonClose.setText("Close");
    jButtonClose.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        jButtonCloseActionPerformed(evt);
      }
    });
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 0;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
    jPanel2.add(jButtonClose, gridBagConstraints);

    jButtonStart.setText("Start");
    jButtonStart.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        jButtonStartActionPerformed(evt);
      }
    });
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 0;
    jPanel2.add(jButtonStart, gridBagConstraints);

    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 6;
    gridBagConstraints.gridwidth = 2;
    jPanel1.add(jPanel2, gridBagConstraints);

    jLabel4.setText("Max. cands (K):");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 1;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
    jPanel1.add(jLabel4, gridBagConstraints);

    jSpinnerK.setModel(new javax.swing.SpinnerNumberModel(Integer.valueOf(1), Integer.valueOf(1), null, Integer.valueOf(1)));
    jSpinnerK.setPreferredSize(new java.awt.Dimension(45, 25));
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 1;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
    jPanel1.add(jSpinnerK, gridBagConstraints);

    jLabel2.setFont(new java.awt.Font("Dialog", 0, 10)); // NOI18N
    jLabel2.setText("(one per line)");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 3;
    gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTHEAST;
    jPanel1.add(jLabel2, gridBagConstraints);

    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 1;
    gridBagConstraints.gridwidth = 16;
    gridBagConstraints.gridheight = 14;
    gridBagConstraints.ipadx = 5;
    gridBagConstraints.ipady = 5;
    gridBagConstraints.weightx = 5.0;
    gridBagConstraints.weighty = 5.0;
    getContentPane().add(jPanel1, gridBagConstraints);
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 2;
    gridBagConstraints.gridwidth = 18;
    getContentPane().add(jLabel3, gridBagConstraints);

    pack();
  }// </editor-fold>//GEN-END:initComponents

  private void jButtonStartActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonStartActionPerformed
    Voting voting = null;
    final List<String> cands = CommonMethods.getCandidatesFromText(jTextPaneCands.
            getText());
    int nVoters = Integer.parseInt(jSpinnerVoters.getValue().toString());
    int K = Integer.parseInt(jSpinnerK.getValue().toString());
    if(K > cands.size()) {
      JOptionPane.showMessageDialog(this, "K must be lower than L");
      return;
    }
<<<<<<< HEAD

    BigInteger[] msg = new BigInteger[2]; 
    msg[0] = BigInteger.ZERO;
    msg[1] = BigInteger.ONE;
    
    Paillier p = new PaillierSimple();
    voting = new Voting(p,K, nVoters, cands,msg);
=======
    // set of possible messages
    BigInteger[] S = new BigInteger[]{BigInteger.ZERO, BigInteger.ONE};
    
    voting = new Voting( new PaillierSimple(), K, nVoters, cands, S);
>>>>>>> Master
     

    final int port = Integer.parseInt(jTextFieldPort.getText());
    final int timeout = CommonMethods.convertMinutesToMiliseconds(Double.
            valueOf(jSpinnerTimeout.getValue().toString()));

    try {
      KeyPairGenerator keygen = KeyPairGenerator.getInstance("Paillier", "CSSI");
      KeyPair kp = keygen.generateKeyPair();
      this.privKey = kp.getPrivate();
      server = new VotingServer(voting, kp);
      server.canEncrypt();

      // create new SwingWorker thread
      SwingWorker worker = new SwingWorker() {

        @Override
        protected VotingServer doInBackground() {
          try {
            server.startVoting(timeout, port);
          }
          catch (IOException | InvalidKeyException | PaillierException ex) {
            LOG.log(Level.SEVERE, ex.getMessage(), ex);
          }
          return server;
        }
        
        @Override
        protected void done() {
          
          JOptionPane.showMessageDialog(rootPane, "Voting ended on port " + port);
          // show voting results
          try {
            server = (VotingServer) get();
            BigInteger[] results = server.getVoting().votingResults(privKey);
            int invalidvotes = server.getVoting().getInvalidVotes();
            JOptionPane.showMessageDialog(rootPane, "Resultado serão apresentados de seguida");

            JDialogVotingResults votingResults = new JDialogVotingResults(JAuthorityMain.getFrames()[0],
                                                                          results,
                                                                          server.getVoting().getCandidateNames(), invalidvotes);
            votingResults.setVisible(true);
          }
          catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPane, ex.getMessage());
            LOG.log(Level.SEVERE, ex.getMessage(), ex);
          }
          
         
          // ??
          this.cancel(true);
        }

        
      };
      // start voting
      worker.execute();
      JOptionPane.showMessageDialog(this,
                                    "Started voting at port " + port + " for " + jSpinnerTimeout.
              getValue() + " minutes");
    }
    catch (NoSuchAlgorithmException | NoSuchProviderException | VotingSchemeException | KeyException ex) {
      JOptionPane.showMessageDialog(this, ex.getMessage());
      LOG.log(Level.SEVERE, ex.getMessage(), ex);
    }
  }//GEN-LAST:event_jButtonStartActionPerformed

    private void jButtonCloseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonCloseActionPerformed
      this.dispose();
    }//GEN-LAST:event_jButtonCloseActionPerformed

  
  /**
   * @param args the command line arguments
   */
  public static void main(String args[]) {
    // set the proper L&F
    try {
      CommonMethods.setLookAndFeel();
      // add provider
      Security.addProvider(new CssiProvider());
    }
    catch (ClassNotFoundException | IllegalAccessException | InstantiationException | UnsupportedLookAndFeelException ex) {
      System.err.println(ex.getMessage());
      LOG.log(Level.SEVERE, ex.getMessage(), ex);
    }

    /* Create and display the form */
    java.awt.EventQueue.invokeLater(new Runnable() {
      @Override
      public void run() {
        new JAuthorityMain().setVisible(true);
      }
    });
  }
  // Variables declaration - do not modify//GEN-BEGIN:variables
  private javax.swing.JButton jButtonClose;
  private javax.swing.JButton jButtonStart;
  private javax.swing.JLabel jLabel1;
  private javax.swing.JLabel jLabel2;
  private javax.swing.JLabel jLabel3;
  private javax.swing.JLabel jLabel4;
  private javax.swing.JLabel jLabel5;
  private javax.swing.JLabel jLabel6;
  private javax.swing.JLabel jLabel7;
  private javax.swing.JPanel jPanel1;
  private javax.swing.JPanel jPanel2;
  private javax.swing.JScrollPane jScrollPane1;
  private javax.swing.JSpinner jSpinnerK;
  private javax.swing.JSpinner jSpinnerTimeout;
  private javax.swing.JSpinner jSpinnerVoters;
  private javax.swing.JTextField jTextFieldPort;
  private javax.swing.JTextPane jTextPaneCands;
  // End of variables declaration//GEN-END:variables
}
