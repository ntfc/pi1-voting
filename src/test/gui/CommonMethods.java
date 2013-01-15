/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test.gui;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.ComboBoxModel;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.UnsupportedLookAndFeelException;
import org.evoting.exception.VotingSchemeException;
import org.evoting.schemes.KOutOfLVoting;
import org.evoting.schemes.OneOutOfLVoting;
import org.evoting.schemes.Voting;
import org.evoting.schemes.YesNoVoting;

/**
 *
 * @author nc
 */
public class CommonMethods {

  public static String[] votingSchemes() {
    String[] schemes = new String[]{
      org.evoting.schemes.YesNoVoting.class.getSimpleName(),
      org.evoting.schemes.OneOutOfLVoting.class.getSimpleName(),
      org.evoting.schemes.KOutOfLVoting.class.getSimpleName()
    };
    return schemes;
  }

  public static ComboBoxModel generateComboBoxModel(Object[] itens) {
    ComboBoxModel model = new DefaultComboBoxModel(itens);
    return model;
  }

  public static void setLookAndFeel() throws ClassNotFoundException,
          InstantiationException, IllegalAccessException,
          UnsupportedLookAndFeelException {
    String os = System.getProperty("os.name");
    if (os.equalsIgnoreCase("Linux")) {
      javax.swing.UIManager.setLookAndFeel(
              "com.sun.java.swing.plaf.gtk.GTKLookAndFeel");
    }
    else {
      javax.swing.UIManager.setLookAndFeel(javax.swing.UIManager.
              getSystemLookAndFeelClassName());
    }
  }

  public static Voting createVotingInstance(String votingType) throws
          ClassNotFoundException, NoSuchMethodException, InstantiationException,
          IllegalAccessException, IllegalArgumentException,
          InvocationTargetException {

    String packageName = "org.evoting.schemes";
    // obtain class
    Class myClass = Class.forName(packageName + '.' + votingType);
    // obatin the empty constructor
    Constructor constructor = myClass.getConstructor();
    // obatin a the Voting(int cands, int votes)
    //Constructor constructor = myClass.getConstructor(int.class, int.class);
    Object instance = constructor.newInstance();

    return (Voting) instance;
  }

  public static YesNoVoting createYesNoVoting(int voters, String c1, String c2) {
    return new YesNoVoting(voters, c1, c2);
  }

  public static OneOutOfLVoting createOneOutOfLVoting(List<String> cs, int vs,
                                                      int b) throws
          VotingSchemeException {
    return new OneOutOfLVoting(cs, vs, b);
  }

  public static KOutOfLVoting createKOutOfLVoting(int k, int b, int vs,
                                                  List<String> cands) throws
          VotingSchemeException {
    return new KOutOfLVoting(k, b, vs, cands);
  }

  public static List<String> getCandidatesFromText(String text) {
    List<String> cands = new ArrayList<>();
    cands.addAll(Arrays.asList(text.split("\n", 0)));
    return cands;
  }

  public static int convertMinutesToMiliseconds(double minutes) {
    return Double.valueOf(60000 * minutes).intValue();
  }
}
