import javax.swing.*;
public class TestIntConstructors {
   public static void main(String[] args) throws Exception {
      Int integer=new Int();
      JOptionPane.showMessageDialog(null,"The default constructor produces "+integer.toString());
      integer=new Int(Integer.parseInt(JOptionPane.showInputDialog("Enter a java int: ")));
      JOptionPane.showMessageDialog(null,"The integer entered was "+integer.toString());
      integer=new Int(JOptionPane.showInputDialog("Enter an arbitrarily large integer: "));
      JOptionPane.showMessageDialog(null,"The integer entered was "+integer.toString());
      System.exit(0);
   }
}
