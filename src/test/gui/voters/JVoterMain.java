package test.gui.voters;

import java.awt.Component;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.UnsupportedLookAndFeelException;
import org.cssi.paillier.cipher.PaillierException;
import org.cssi.provider.CssiProvider;
import org.evoting.exception.NumberOfVotesException;
import org.evoting.exception.VariableNotSetException;
import org.evoting.exception.VotingSchemeException;
import org.evoting.schemes.Voting;
import org.evoting.voter.VoterClient;
import test.gui.CommonMethods;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 */
public class JVoterMain extends javax.swing.JFrame {

  private VoterClient voter;
  private PublicKey key;
  private static final Logger LOG = Logger.getLogger(JVoterMain.class.getName());

  /**
   * Creates new form JVoterMain
   */
  public JVoterMain() {
    initComponents();
    setLocationRelativeTo(null);
    jLabel1.setVisible(false);
    jButton1.setVisible(false);
  }

  /**
   * This method is called from within the constructor to
   * initialize the form.
   * WARNING: Do NOT modify this code. The content of this method is
   * always regenerated by the Form Editor.
   */
  @SuppressWarnings("unchecked")
  // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
  private void initComponents() {
    java.awt.GridBagConstraints gridBagConstraints;

    jPanel1 = new javax.swing.JPanel();
    jButtonConnect = new javax.swing.JButton();
    jLabel1 = new javax.swing.JLabel();
    jPanel2 = new javax.swing.JPanel();
    jPanelOptions = new javax.swing.JPanel();
    jButton1 = new javax.swing.JButton();
    jButton2 = new javax.swing.JButton();

    setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
    setTitle("Voter");
    setMinimumSize(new java.awt.Dimension(455, 296));
    setPreferredSize(new java.awt.Dimension(455, 296));
    getContentPane().setLayout(new java.awt.GridBagLayout());

    jPanel1.setLayout(new java.awt.GridBagLayout());

    jButtonConnect.setText("Connect");
    jButtonConnect.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        jButtonConnectActionPerformed(evt);
      }
    });
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridwidth = 2;
    jPanel1.add(jButtonConnect, gridBagConstraints);

    jLabel1.setText("Opções:");
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 1;
    jPanel1.add(jLabel1, gridBagConstraints);

    jPanel2.setLayout(new java.awt.GridBagLayout());

    jPanelOptions.setLayout(new java.awt.GridBagLayout());
    jPanel2.add(jPanelOptions, new java.awt.GridBagConstraints());

    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 1;
    gridBagConstraints.gridy = 1;
    jPanel1.add(jPanel2, gridBagConstraints);

    jButton1.setText("Submit");
    jButton1.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        jButton1ActionPerformed(evt);
      }
    });
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 2;
    gridBagConstraints.gridwidth = 2;
    jPanel1.add(jButton1, gridBagConstraints);

    jButton2.setText("Close");
    jButton2.setMaximumSize(new java.awt.Dimension(88, 29));
    jButton2.setMinimumSize(new java.awt.Dimension(88, 29));
    jButton2.setPreferredSize(new java.awt.Dimension(88, 29));
    jButton2.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        jButton2ActionPerformed(evt);
      }
    });
    gridBagConstraints = new java.awt.GridBagConstraints();
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 3;
    gridBagConstraints.gridwidth = 2;
    jPanel1.add(jButton2, gridBagConstraints);

    getContentPane().add(jPanel1, new java.awt.GridBagConstraints());

    pack();
  }// </editor-fold>//GEN-END:initComponents

  private void jButtonConnectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonConnectActionPerformed
    JDialogConnect connect = new JDialogConnect(this, true);
    this.voter = null;
    connect.setVisible(true);
    Socket cliSocket = connect.showDialog();
    if (cliSocket != null) {
      this.jButtonConnect.setVisible(false);
      try {
        this.voter = new VoterClient(cliSocket);
        this.voter.setUpVoting();
        // show voting options
        generateVotingOptions();
        //show buttons
        jLabel1.setVisible(true);
        jButton1.setVisible(true);
      }
      catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | VotingSchemeException ex) {
        JOptionPane.showMessageDialog(this, ex.getMessage());
        LOG.log(Level.SEVERE, ex.getMessage(), ex);
        this.dispose();
      }
    }
    else {
      JOptionPane.showMessageDialog(this, "Error connecting server");
      this.dispose();
    }
  }//GEN-LAST:event_jButtonConnectActionPerformed

  private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
    Voting voting = this.voter.getVoting();
    //Ballot b = new Ballot(voting.getNrCandidates());

    Component[] options = jPanelOptions.getComponents();


    int size = 0;

    //number of selected candidates
    for (Component c : options) {
      if (((JCheckBox) c).isSelected()) {
        size++;
      }

    }
    int[] arrayVotes = new int[size];


    //selected candidates
    int j = 0;
    for (int i = 0; i < options.length; i++) {
      if (((JCheckBox) options[i]).isSelected()) {
        int opcao = i;
        arrayVotes[j] = opcao;
        j++;
      }
    }
    
    
    try {
      
      //submit votes
      voter.submitVote(arrayVotes);
      JOptionPane.showMessageDialog(this, "Vote submitted");
    }
    catch (NumberOfVotesException | VotingSchemeException | InvalidKeyException | IOException | PaillierException | VariableNotSetException ex) {
      JOptionPane.showMessageDialog(this, ex.getMessage());
      LOG.log(Level.SEVERE, ex.getMessage(), ex);
    }
    
    
    this.dispose();
  }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
      this.dispose();
    }//GEN-LAST:event_jButton2ActionPerformed

  private void generateVotingOptions() {
    Voting voting = this.voter.getVoting();
    if(voting != null) {
      List<String> cands = voting.getCandidateNames();
      for (String cand : cands) {
        JCheckBox check = new JCheckBox(cand);
        jPanelOptions.add(check);
      }
    }
  }

  /**
   * @param args the command line arguments
   */
  public static void main(String args[]) {
    try {
      CommonMethods.setLookAndFeel();
      Security.addProvider(new CssiProvider());
    }
    catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException ex) {
      LOG.log(Level.SEVERE, ex.getMessage(), ex);
    }
    /*
     * Create and display the form
     */
    java.awt.EventQueue.invokeLater(new Runnable() {
      @Override
      public void run() {
        new JVoterMain().setVisible(true);
      }
    });
  }
  // Variables declaration - do not modify//GEN-BEGIN:variables
  private javax.swing.JButton jButton1;
  private javax.swing.JButton jButton2;
  private javax.swing.JButton jButtonConnect;
  private javax.swing.JLabel jLabel1;
  private javax.swing.JPanel jPanel1;
  private javax.swing.JPanel jPanel2;
  private javax.swing.JPanel jPanelOptions;
  // End of variables declaration//GEN-END:variables
}
