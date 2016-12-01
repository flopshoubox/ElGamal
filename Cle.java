package devoir2_secu;

import java.math.BigInteger;

public class Cle {
	
	private BigInteger a; // a est la clé privée, >1 et < p
	private BigInteger y; // y est égal à (g^a) mod p
	private BigInteger q; // q est un nombre premier sur lequel va se baser la sécurté du système.
	private BigInteger p; // p est un premier tq p = 2q+1
	private BigInteger g; // g est un générateur de Z* p qui génère un sous-groupe d'ordre q
	private int nbBits;
	
	public Cle (BigInteger a, BigInteger g, BigInteger gExpAmodP, BigInteger p, int nbBits){
		this.a = a;
		this.g = g;
		this.y = g.modPow(a, p);
		this.p = p;
		this.nbBits = nbBits;
	}
	
	public Cle (BigInteger a){
		this.a = a;
		this.nbBits = 32;
	}
	
	public void set_a (BigInteger a) {
		this.a = a;
	}
	
	public void set_q (BigInteger q) {
		this.q = q;
	}
	
	public void set_g (BigInteger g) {
		this.g = g;
	}
	
	public void set_y (BigInteger y) {
		this.y = y;
	}
	
	public void set_p (BigInteger p) {
		this.p = p;
	}
	
	public void set_nbBits (int nbBits) {
		this.nbBits = nbBits;
	}
	
	public BigInteger get_a (){
		return this.a;
	}
	
	public BigInteger get_q (){
		return this.q;
	}

	public BigInteger get_g () {
		return this.g;
	}
	
	public BigInteger get_y () {
		return this.y;
	}
	
	public BigInteger get_p () {
		return this.p;
	}
	public int get_nbBits () {
		return this.nbBits;
	}
}