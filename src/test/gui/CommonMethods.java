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
import javax.swing.UnsupportedLookAndFeelException;
import org.evoting.schemes.Voting;

/**
 *
 * @author nc
 */
public class CommonMethods {


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

  

  public static List<String> getCandidatesFromText(String text) {
    List<String> cands = new ArrayList<>();
    cands.addAll(Arrays.asList(text.split("\n", 0)));
    return cands;
  }

  public static int convertMinutesToMiliseconds(double minutes) {
    return Double.valueOf(60000 * minutes).intValue();
  }
}
