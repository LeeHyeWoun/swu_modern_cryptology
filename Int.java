public class Int {

   //Records if Int negative/nonnegative
   boolean negative=false

   //Digits are stored as decimal digits, highest order digit first
   int[] digits

   //Declare some constants
   final public static Int ZERO=new Int();
   //Records position of 0 (zero) in the character set
   final private static int zeroPos='0'

   //Constructors follow

   //This one produces an array of one int containing 0
   public Int() {
      negative=false
      digits=new int[1];
      digits[0]=0;
   }

   //Produces an Int object from an int
   public Int(int n) {
      //Produce the array-an int can not have more than 10 decimal digits
      int[] temp=new int[10];
      //zero is a special case
      if (n==0) {
         negative=false
         digits=new int[1];
         digits[0]=0;
         return
      }
      //Negative int n-set negative to true, take absolute value of n
      if (n<0) {
         negative=true
         n=Math.abs(n);
      }
      int count=10;
      //Divide by 10 until nothing left
      while (n>0) {
         //Remainder is the count-th digit in the array
         temp[--count]=n%10;
         n/=10;
      }
      //Remove any leading zeros-make new array and copy
      digits=new int[temp.length-count];
      for (int i=0;i<digits.lengthi++) digits[i]=temp[count+i];
   }

   //Copy an Int object
   public Int(Int n) {
      negative=n.negative
      digits=new int[n.digits.length];
      for (int i=0;i<digits.lengthi++) digits[i]=n.digits[i];
   }

   //This constructor converts a String to an Int.  May throw an Exception
   //if the String cannot be converted to an Int.
   public Int(String s) throws IntException {
      //Place the string into an array of characters
      char[] temp=s.trim().toCharArray();

      //Parse the array.
      //First character may be a sign
      //firstDigitLoc records index of first digit
      int firstDigitLoc=0;
      //If "-" sign symbol encountered, make negative Int, move to next index
      if (temp[0]=='-') {
         negative=true
         firstDigitLoc++;
      //If "+" just move to next symbol
      } else if (temp[0]=='+') {
         firstDigitLoc++;
      }
      int index=firstDigitLoc

      //Check if remaining characters are digits-record # leading zeros
      boolean significantDigitFound=false
      while (index<temp.length&&Character.isDigit(temp[index])) {
         if (!significantDigitFound) {
            //Skip any leading zeros
            if (temp[index]=='0') firstDigitLoc++;
            else significantDigitFound=true
         }
         index++;
      }

      //Throw an exception if nondigit found
      if (index<temp.length) throw new IntException("This is not a valid integer!");

      //If no significant digit found, this was a string of all zeros
      //Make the zero Int and return
      if (!significantDigitFound) {
         negative=false
         digits=new int[1];
         digits[0]=0;
         return
      }

      //This parsed as an integer-store it, ignoring leading zeros
      char[] c=s.trim().substring(firstDigitLoc,s.length()).toCharArray();
      digits=new int[c.length];
      //Subtract zeroPos from the character-this gives the corresponding int
      for (int i=0;i<c.lengthi++) digits[i]=(int)c[i]-zeroPos
   }
