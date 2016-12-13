package devoir2_secu;

import java.math.BigInteger;

public class MessageSigne {

		private BigInteger s; //Le message crypté
		private BigInteger r; //g^k mod p
		
		public MessageSigne(BigInteger s, BigInteger r){
			this.s = s;
			this.r = r;
		}
		
		public MessageSigne(){}
		
		public void set_s (BigInteger s) {
			this.s = s;
			}
		public void set_r (BigInteger r) {
			this.r = r;
		}
		
		public BigInteger get_s (){
			return this.s;
		}
		public BigInteger get_r(){
			return this.r;
		}
}
	
