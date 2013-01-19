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
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.paillier.cipher.PaillierSimple;
import org.cssi.provider.CssiProvider;
import org.evoting.authority.VotingServer;
import org.evoting.exception.VotingSchemeException;
import org.evoting.schemes.KOutOfLVoting;
import org.evoting.schemes.OneOutOfLVoting;
import org.evoting.schemes.Voting;
import org.evoting.schemes.YesNoVoting;
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
    jComboVotingSchemes = new javax.swing.JComboBox();
    jLabel2 = new javax.swing.JLabel();
    jLabel3 = new javax.swing.JLabel();
    jSpinnerBase = new javax.swing.JSpinner();
    jScrollPane1 = new javax.swing.JScrollPane();
    jTextPaneCands = new javax.swing.JTextPane();
    jLabel5 = new javax.swing.JLabel();
    jTextFieldPort = new javax.swing.JTextField();
    jLabel6 = new javax.swing.JLabel();
    jSpinnerTimeout = new javax.swing.JSpinner();
    jLabel7 = new javax.swing.JLabel();
    jPanel2 = new javax.swing.JPanel();
    jButtonStart = new javax.swing.JButton();
    jLabel4 = new javax.swing.JLabel();
    jSpinnerK = new javax.swing.JSpinner();

    setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
    getContentPane().setLayout(new java.awt.GridBagLayout());

    jPanel1.setLayout(new java.awt.GridBagLayout());

    jLabel1.setText("Nr. voters:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 1;
    jPanel1.add(jLabel1, gridBagConstraints);
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 1;
    jPanel1.add(jSpinnerVoters, gridBagConstraints);

    jComboVotingSchemes.setModel(CommonMethods.generateComboBoxModel(CommonMethods.votingSchemes()));
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 0;
    jPanel1.add(jComboVotingSchemes, gridBagConstraints);

    jLabel2.setText("Voting scheme:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 0;
    jPanel1.add(jLabel2, gridBagConstraints);

    jLabel3.setText("Base:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 2;
    jPanel1.add(jLabel3, gridBagConstraints);
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 2;
    jPanel1.add(jSpinnerBase, gridBagConstraints);

    jScrollPane1.setMinimumSize(new java.awt.Dimension(150, 100));
    jScrollPane1.setPreferredSize(new java.awt.Dimension(150, 100));
    jScrollPane1.setViewportView(jTextPaneCands);

    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 4;
    jPanel1.add(jScrollPane1, gridBagConstraints);

    jLabel5.setText("Server port:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 5;
    jPanel1.add(jLabel5, gridBagConstraints);

    jTextFieldPort.setColumns(5);
    jTextFieldPort.setText("4546");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 5;
    jPanel1.add(jTextFieldPort, gridBagConstraints);

    jLabel6.setText("Timeout (min):");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 6;
    jPanel1.add(jLabel6, gridBagConstraints);

    jSpinnerTimeout.setModel(new javax.swing.SpinnerNumberModel(Double.valueOf(1.0d), Double.valueOf(0.1d), null, Double.valueOf(1.0d)));
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 6;
    jPanel1.add(jSpinnerTimeout, gridBagConstraints);

    jLabel7.setText("Candidates (one per line):");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 4;
    jPanel1.add(jLabel7, gridBagConstraints);

    jPanel2.setLayout(new java.awt.GridBagLayout());

    jButtonStart.setText("Start");
    jButtonStart.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        jButtonStartActionPerformed(evt);
      }
    });
    jPanel2.add(jButtonStart, new java.awt.GridBagConstraints());

    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 7;
    gridBagConstraints.gridwidth = 2;
    jPanel1.add(jPanel2, gridBagConstraints);

    jLabel4.setText("Max. cands (K):");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 3;
    jPanel1.add(jLabel4, gridBagConstraints);

    jSpinnerK.setModel(new javax.swing.SpinnerNumberModel(Integer.valueOf(1), Integer.valueOf(1), null, Integer.valueOf(1)));
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 3;
    jPanel1.add(jSpinnerK, gridBagConstraints);

    getContentPane().add(jPanel1, new java.awt.GridBagConstraints());

    pack();
  }// </editor-fold>//GEN-END:initComponents

  private void jButtonStartActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonStartActionPerformed
    String votingType = (String) jComboVotingSchemes.getSelectedItem();
    Voting voting = null;
    List<String> cands = CommonMethods.getCandidatesFromText(jTextPaneCands.
            getText());
    int nVoters = Integer.parseInt(jSpinnerVoters.getValue().toString());
    int base = Integer.parseInt(jSpinnerBase.getValue().toString());
    int K = Integer.parseInt(jSpinnerK.getValue().toString());
    if(K > cands.size()) {
      JOptionPane.showMessageDialog(this, "K must be lower than L");
      return;
    }

    switch (votingType) {
      case "YesNoVoting":
        if (! validateYesNo(cands)) {
          return;
        }
        // create yes no voting
        voting = new YesNoVoting(nVoters, cands.get(0), cands.get(1));
        break;
      case "OneOutOfLVoting":
        try {
          voting = new OneOutOfLVoting(cands, nVoters, base);
        }
        catch(VotingSchemeException ex) {
          JOptionPane.showMessageDialog(this, ex.getMessage());
          return;
        }
        break;
      case "KOutOfLVoting":
        try {
          voting = new KOutOfLVoting(K, base, nVoters, cands);
        }
        catch(VotingSchemeException ex) {
          JOptionPane.showMessageDialog(this, ex.getMessage());
          return;
        }
        break;
      default:
        JOptionPane.showMessageDialog(this, "Voting scheme error");
        break;

    }

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
      // TODO: Burns, isto está bem?
      SwingWorker worker = new SwingWorker() {

        @Override
        protected void done() {
          JOptionPane.showMessageDialog(rootPane, "Voting ended on port " + port);
          // show voting results
          try {
            BigInteger tally = server.getVoting().tallying(privKey);
            // TODO: fix
            //String res = server.getVoting().votingResults(new PaillierSimple().dec(privKey, tally));
            //JOptionPane.showMessageDialog(rootPane, res);
          }
          catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPane, ex.getMessage());
            LOG.log(Level.SEVERE, ex.getMessage(), ex);
          }
          // ??
          this.cancel(true);
        }

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

  @Deprecated
  private boolean validateYesNo(List<String> cands) {
    if (cands.size() != 2) {
      JOptionPane.showMessageDialog(this,
                                    "Wrong number of candidates. Must be equal to 2");
      return false;
    }
    return true;
  }
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
  private javax.swing.JButton jButtonStart;
  private javax.swing.JComboBox jComboVotingSchemes;
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
  private javax.swing.JSpinner jSpinnerBase;
  private javax.swing.JSpinner jSpinnerK;
  private javax.swing.JSpinner jSpinnerTimeout;
  private javax.swing.JSpinner jSpinnerVoters;
  private javax.swing.JTextField jTextFieldPort;
  private javax.swing.JTextPane jTextPaneCands;
  // End of variables declaration//GEN-END:variables
}
