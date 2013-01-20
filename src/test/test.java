/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author nc
 */
public class test {

  public static BigInteger tallyDec = new BigInteger("235");
  public static int base = 25;
  public static int K = 1, L = 3;
  public static List<String> cands = new ArrayList<>();
  private static final Logger LOG = Logger.getLogger(test.class.getName());
  private static int votersWhoVoted = 19;

  public static String results() {
    StringBuilder s = new StringBuilder("Results\n");
    LOG.log(Level.INFO, "tallyDec = {0}", tallyDec.toString());
    // convert tallyDec from base 10 to base defined in the voting scheme
    String tallyBase = tallyDec.toString(base);
    LOG.log(Level.INFO, "tally base {0} = {1}", new Object[]{base, tallyBase});
    
    // add zeros
    String tallyBaseStr = paddingZeros(tallyBase, L);

    // count non blank votes
    int nonBlank = 0;
    for (int j = (L - 1), index = 0; j >= 0; j--, index++) {
      // count votes for candidate_index
      char nVotesChar = tallyBaseStr.charAt(j);
      // convert from base to base 10
      int nVotes = Integer.parseInt(String.valueOf(nVotesChar), base);
      nonBlank += nVotes;
      // get candidate name from the list of candidates
      String candName = cands.get(index);
      // and append the number of votes in the candidate
      s.append(candName).append(" : ").append(nVotes).append("\n");
      LOG.log(Level.INFO, "votes for candidate {0}(index {1}) = {2}",
              new Object[]{candName,
                index, nVotes});
    }
    int blankVotes = votersWhoVoted - nonBlank;
    s.append("TOTAL: ").append(nonBlank).append(" votos, ");
    s.append(blankVotes).append(" em branco").append("\n");
    return s.toString().trim(); // trim to remove useless \n
  }

  public static String paddingZeros(String n, int strLength) {
    StringBuilder sb = new StringBuilder();

    // append zeros
    for(int toprepend = strLength-n.length(); toprepend > 0; toprepend--) {
      sb.append('0');
    }
    // append string n
    sb.append(n);
    return sb.toString();
  }

  public static void main(String[] args) {
    cands.add("A");
    cands.add("B");
    cands.add("C");
    cands.add("D");
    cands.add("E");
    String s = results();
    System.out.println(s);




  }
}
