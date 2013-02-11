/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package test.gui.authority;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import javax.swing.JRootPane;
import javax.swing.table.DefaultTableModel;

/**
 *
 * @author nc
 */
public class JDialogVotingResults extends javax.swing.JDialog {
  private Map<Integer,BigInteger> results;
  private List<String> candidates;
  private int invalidvotes;
  private int blankVotes=0;
	/** Creates new form JDialogVotingResults */
	public JDialogVotingResults(java.awt.Frame parent, Map<Integer,BigInteger> res, List<String> cands, int invVotes, int blankVotes) {
		super(parent);
		initComponents();
    this.results = res;
    this.candidates = cands;
    this.invalidvotes = invVotes;
    this.blankVotes = blankVotes;
    setLocationRelativeTo(null);
    this.setVotingResults();

	}
  
  private void setVotingResults() {
    for(Integer i : results.keySet()) {
      String t = jTextArea1.getText();
      t += candidates.get(i).concat(" : ").concat(results.get(i).toString()).concat(
              "\n");
      jTextArea1.setText(t);
    }
    //print black votes
    String t = jTextArea1.getText();
    t += "Votos brancos".concat(" : ")+this.blankVotes+
              "\n";
    jTextArea1.setText(t);
    //print invalid votes
    String t1 = jTextArea1.getText();
    t1 += "Votos nulos : ".concat(String.valueOf(invalidvotes)).concat("\n");
    jTextArea1.setText(t1);
  }

	/** This method is called from within the constructor to
	 * initialize the form.
	 * WARNING: Do NOT modify this code. The content of this method is
	 * always regenerated by the Form Editor.
	 */
	@SuppressWarnings("unchecked")
  // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
  private void initComponents() {

    jPanel1 = new javax.swing.JPanel();
    jScrollPane2 = new javax.swing.JScrollPane();
    jTextArea1 = new javax.swing.JTextArea();

    setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
    setTitle("Resultados:");
    getContentPane().setLayout(new java.awt.GridBagLayout());

    jPanel1.setLayout(new java.awt.GridBagLayout());
    getContentPane().add(jPanel1, new java.awt.GridBagConstraints());

    jTextArea1.setEditable(false);
    jTextArea1.setColumns(30);
    jTextArea1.setRows(15);
    jTextArea1.setTabSize(2);
    jScrollPane2.setViewportView(jTextArea1);

    getContentPane().add(jScrollPane2, new java.awt.GridBagConstraints());

    pack();
  }// </editor-fold>//GEN-END:initComponents


  // Variables declaration - do not modify//GEN-BEGIN:variables
  private javax.swing.JPanel jPanel1;
  private javax.swing.JScrollPane jScrollPane2;
  private javax.swing.JTextArea jTextArea1;
  // End of variables declaration//GEN-END:variables

}
