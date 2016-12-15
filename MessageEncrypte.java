
import java.math.BigInteger;

public class MessageEncrypte {

		private String c; 		//Le message crypté
		private BigInteger Y;	//g^b mod p
		
		public MessageEncrypte(String c, BigInteger Y){
			this.c = c;
			this.Y = Y;
		}
		
		public MessageEncrypte(){}
		
		public void set_c (String c) {
			this.c = c;
		}
		public void set_Y (BigInteger Y) {
			this.Y = Y;
		}
		
		public String get_c (){
			return this.c;
		}
		public BigInteger get_Y(){
			return this.Y;
		}
}
	
