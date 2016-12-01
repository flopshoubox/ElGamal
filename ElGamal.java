package devoir2_secu;



//notes :
//le nb premier doit être supérieur à 10 sans quoi l'encryption n'est possible qu'avec 0 caractère



import java.math.BigInteger;
import java.util.Random;
import java.security.SecureRandom;

public class ElGamal {
	
	private static int nbBits = 12;
	
	public static Cle GenererClesElgamal(BigInteger a){
		Random rand = new SecureRandom();
		boolean cleValide = false;
		boolean generateurValide = false;
		BigInteger bigTwo = new BigInteger("2");
		Cle cleK = new Cle(a);
		cleK.set_nbBits(nbBits);
		
		BigInteger compteur = BigInteger.ZERO;
		
		while (cleValide != true){
			
			//On va commencer par chercher un nombre premier p=2q+1 premier supérieur à "a"
			//avec q premier aussi.
			
			cleK.set_q(BigInteger.probablePrime(cleK.get_nbBits()-1, rand));
			//Ici on vérifie que 2*q+1 soit supérieur à "a"
			while ((((cleK.get_q().add(cleK.get_q())).add(BigInteger.ONE)).compareTo(cleK.get_a())) == -1){
				cleK.set_q(BigInteger.probablePrime(cleK.get_nbBits()-1, rand));
				System.out.println((cleK.get_q().add(cleK.get_q())).add(BigInteger.ONE));
			}
			//On construit alors p tel que p=2q+1
			cleK.set_p((cleK.get_q().add(cleK.get_q())).add(BigInteger.ONE)); //p = 2 * q +1
		
			//On regarde ensuite si p est premier.
			//la valeur dans le test de proba est tel que le nombre est déclaré premier avec une proba de 1-1/(2^certitude)
			//Ici avec 20 on a une chance sur 1 million que le nombre ne soit finalement pas premier.
			if (cleK.get_p().isProbablePrime(20)){ 
				cleValide = true;	
			}
		}
		
		//On va maintenant trouver un générateur g>1
		cleK.set_g(BigInteger.ONE);
		while (generateurValide != true){
			compteur = BigInteger.ZERO;
			cleK.set_g(cleK.get_g().add(BigInteger.ONE));
			
			//On vérifie si (g^q)mod p = 1 ce qui signifie que g génère un sous groupe de taille q.
			if ((cleK.get_g().modPow(cleK.get_q(),cleK.get_p())).compareTo(BigInteger.ONE) == 0 && (cleK.get_g().modPow(bigTwo,cleK.get_p())).compareTo(BigInteger.ONE) != 0){ // ==0 car la fonction retourne 0 quand il y a égalité des expressions
				generateurValide = true;
			}
		}
		
		cleK.set_y(cleK.get_g().modPow(cleK.get_a(), cleK.get_p()));
		System.out.println("a : " + cleK.get_a().toString());
		System.out.println("g : " + cleK.get_g().toString());
		System.out.println("y : " + cleK.get_y().toString());
		System.out.println("q : " + cleK.get_q().toString());
		System.out.println("p : " + cleK.get_p().toString());
		
		
		return cleK;
	}
	
	public static MessageEncrypte EncrypterElGamal (String m, Cle cleK){
		m = m.toUpperCase();

		Random rand = new SecureRandom();
		MessageEncrypte C = new MessageEncrypte();
		C.set_c("");
		BigInteger b = new BigInteger(nbBits, rand);
System.out.println("La clé temporaire b est tel que b = " + b.toString());
		
		String M = "";
		char charBuffer;
		BigInteger longueurMessage = BigInteger.ZERO;
		BigInteger compteurBig = BigInteger.ZERO;
		String stringBuffer;
		BigInteger bigIntBuffer;
		BigInteger nbChiffresDansP = BigInteger.ZERO;
		
		//On va transformer ici le message m à crypter en une suite de code ASCII dans un BigNumber
		m += "#";
		while (m.charAt(0) != "#".charAt(0)){
			charBuffer = m.charAt(0);
			m = m.substring(1);
			M += (int)charBuffer;
			
		}
		
		//On va déterminer la longueur du message à coder une fois qu'il a été transformé en valeur ASCII
		String copieM = M;
		copieM += "#";
		while (copieM.charAt(0) != "#".charAt(0)){
			longueurMessage = longueurMessage.add(BigInteger.ONE);
			copieM = copieM.substring(1);
		}
		
		//Nous allons chercher ici la taille des groupes de chiffres à crypter.
		String stringP = cleK.get_p().toString();
		stringP += "#";
		
		while (stringP.charAt(0) != "#".charAt(0)){
			nbChiffresDansP = nbChiffresDansP.add(BigInteger.ONE);
			stringP = stringP.substring(1);
		}
		BigInteger parametre;
		String blocEncode;
		String stringBlocEncode;
		BigInteger nbChiffresBloc;
		
		//Dans cette boucle on va traiter le message
		while(longueurMessage.compareTo(BigInteger.ZERO) != 0){
			compteurBig = BigInteger.ZERO; //remise à zro du compteur de caractère
			stringBuffer = ""; //vidage du buffer
			
			
			//On regarde 
			if (longueurMessage.compareTo(nbChiffresDansP) == -1){
				parametre = longueurMessage;
			}
			else {
				parametre = nbChiffresDansP.subtract(BigInteger.ONE);
			}
			
			
			//On remplit le buffer avec le nombre de chiffre suivant "parametre"
			while (compteurBig.compareTo(parametre) == -1){
				stringBuffer += M.charAt(0);
				M = M.substring(1);
				compteurBig = compteurBig.add(BigInteger.ONE);
			}
			//Buffer contenant la valeur décimale d'une chaine de caractère de taille p-1
			bigIntBuffer = new BigInteger(stringBuffer); 			
			
			// On va en une étape encrypter le bloc en cours de traitement et ajouter le résultat à C
			//Calcul d'un bloc : M x y^b mod p = M x (g^a mod p)^b mod p = M x (g^ab mod p)
			
			blocEncode = ((bigIntBuffer.multiply(cleK.get_y().modPow(b, cleK.get_p()))).mod(cleK.get_p())).toString();
			
			//Nous allons chercher ici la taille des bloc encodés.
			//Si le bloc est plus petit que le nombre de chiffres composant le nombre p on complète avec des 0
			stringBlocEncode = blocEncode.toString();
			stringBlocEncode += "#";
			nbChiffresBloc = BigInteger.ZERO;
			//On compte le nombre de chiffre dans le bloc
			while (stringBlocEncode.charAt(0) != "#".charAt(0)){
				nbChiffresBloc = nbChiffresBloc.add(BigInteger.ONE);
				stringBlocEncode = stringBlocEncode.substring(1);				
			}

			//On ajoute les zero si besoin
			compteurBig = BigInteger.ZERO;
			while (compteurBig.compareTo(nbChiffresDansP.subtract(nbChiffresBloc)) == -1){
				compteurBig = compteurBig.add(BigInteger.ONE);
				blocEncode = "0" + blocEncode;
				}
			
			//On ajoute le bloc à la chaine C.c
			C.set_c(C.get_c() + blocEncode);
			longueurMessage = longueurMessage.subtract(parametre);
		}
		//Calcul de Y = g^b mod p
		C.set_Y(cleK.get_g().modPow(b, cleK.get_p()));
		return C;
	}
	
	public static String DecrypterElGamal (MessageEncrypte C, Cle cleK){
		String c = C.get_c();
		String m = "";
		String M = "";
		BigInteger compteurBig;
		BigInteger longueurP = BigInteger.ZERO;
		String copieP = cleK.get_p().toString();
		String bufferString;
		BigInteger bufferBig;
		int bufferInt;
		
		//On calcule ci-dessous (Y^a)^-1 mod p = (((g^b)^a)^-1)
		BigInteger invSharedSecret = (C.get_Y().modPow(cleK.get_a(), cleK.get_p())).modInverse(cleK.get_p());
		
		
		//Boucle de comptage du nombre de digit dans P.
		copieP += "#";
		while (copieP.charAt(0) != "#".charAt(0)){
			longueurP = longueurP.add(BigInteger.ONE);
			copieP = copieP.substring(1);
		}
		
		//Boucle de décryptage
		c += "#";
		while (c.charAt(0) != "#".charAt(0)){
			//On va décrypter par bloc de "longueurP" caractères.
			compteurBig = BigInteger.ZERO;
			bufferString = "";
			while (compteurBig.compareTo(longueurP) != 0){
				bufferString += c.charAt(0);
				c = c.substring(1);
				compteurBig = compteurBig.add(BigInteger.ONE);
			}
			bufferBig = new BigInteger(bufferString);
			M += (bufferBig.multiply(invSharedSecret)).mod(cleK.get_p()).toString();
		}
		
		M += "#";
		while (M.charAt(0) != "#".charAt(0)){
			bufferInt = Integer.parseInt(M.substring(0, 2));
			M = M.substring(2);
			m += Character.toString((char) bufferInt);
		}
		
		return m;
	}
	
	public static MessageSigne SignerElGamal (String m, Cle cleK){
		Random rand = new SecureRandom();
		MessageSigne mSigne = new MessageSigne();
		char charBuffer;
		String stringBuffer = "";
		BigInteger M;
		BigInteger hDeM;
		BigInteger k;
		
		m += "#";
		while (m.charAt(0) != "#".charAt(0)){
			charBuffer = m.charAt(0);
			m = m.substring(1);
			stringBuffer += (int)charBuffer;
		}
		
		M = new BigInteger(stringBuffer);
		hDeM = M.modPow(BigInteger.ONE.add(BigInteger.ONE), cleK.get_p());
		
		//La condition sur l'nsemble de la signature est que s soit différent de zero
		mSigne.set_s(BigInteger.ZERO);
		while (mSigne.get_s().compareTo(BigInteger.ZERO) == 0){
			//On va générer un nombre aléatoire compris entre 1 et (nbBits + 1)
			// q est sur nbBits donc 2*q est sur nbBits + 1 donc l'intervalle [1, p-1]
			//équivault à un random sur (nbBits+1) + 1
			while (true){
				k = new BigInteger(nbBits + 1, rand).add(BigInteger.ONE); 
				if (k.compareTo(BigInteger.ONE) == 1 && k.compareTo(cleK.get_p().subtract(BigInteger.ONE)) == -1 && k.gcd(cleK.get_p().subtract(BigInteger.ONE)).compareTo(BigInteger.ONE) == 0){ //On vérifie que k est bien plus petit que p.
					break;
				}
			}
			
			//calcul de r
			mSigne.set_r(cleK.get_g().modPow(k, cleK.get_p()));
			
			//calcul de s
			mSigne.set_s( (k.modInverse(cleK.get_p().subtract(BigInteger.ONE))).multiply(hDeM.subtract(cleK.get_a().multiply(mSigne.get_r())) ).mod(cleK.get_p().subtract(BigInteger.ONE)));
			
		}
		
		return mSigne;
	}
	
	public static boolean VerifierSignatureElGamal (String m, MessageSigne rs, Cle cleK){
		char charBuffer;
		String stringBuffer = "";
		BigInteger M;
		BigInteger hDeM;
		
		
		
		m += "#";
		while (m.charAt(0) != "#".charAt(0)){
			charBuffer = m.charAt(0);
			m = m.substring(1);
			stringBuffer += (int)charBuffer;
		}
		
		M = new BigInteger(stringBuffer);
		hDeM = M.modPow(BigInteger.ONE.add(BigInteger.ONE), cleK.get_p());
		return ( cleK.get_g().modPow(hDeM,cleK.get_p()).compareTo(((cleK.get_y().modPow(rs.get_r(),cleK.get_p())).multiply(rs.get_r().modPow(rs.get_s(),cleK.get_p()))).mod(cleK.get_p())) == 0 );
	}
	
 	public static void main(String[] args) {
		// TODO Auto-generated method stub
		BigInteger a = new BigInteger("7");
		
		System.out.println("El Gamal");
		System.out.println("Génération de la clé à partir de a = " + a.toString());
		System.out.println("Le nombre premier q dans p = 2*q+1 sera sur " + Integer.toString(nbBits)  + " bits.");
		MessageEncrypte C = new MessageEncrypte();
		Cle test = GenererClesElgamal(a);
		
		String messageAEncrypter = "QWERTZ";
		System.out.println("\nMessage à encrpter : " + messageAEncrypter);
		C = EncrypterElGamal(messageAEncrypter, test);
		
		System.out.println("\nLe message encrypté est = " + C.get_c());
		System.out.println("La clé temporaire encryptée vaut =  " + C.get_Y());
		
		String message;
		message = DecrypterElGamal(C, test);
		System.out.println("\nMessage décrypté = " + message);
		
		String messageASigner = "COUCOU";
		System.out.println("\nSignature du message = " + messageASigner);
		MessageSigne rs = SignerElGamal(messageASigner,test);
		System.out.println("r = " + rs.get_r().toString());
		System.out.println("s = " + rs.get_s().toString());
		
		System.out.println("\nLa signature est = " + VerifierSignatureElGamal(messageASigner, rs, test));

		
	}
}
