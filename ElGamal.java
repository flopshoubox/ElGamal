
//notes :
//le nb premier doit être supérieur à 10 sans quoi l'encryption n'est possible qu'avec 0 caractère


import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;
import java.security.SecureRandom;

public class ElGamal {
	
	
	public static Cle GenererClesElgamal(BigInteger a, int nbBits){
		Random rand = new SecureRandom();
		boolean cleValide = false;
		boolean generateurValide = false;
		BigInteger bigTwo = new BigInteger("2");
		Cle cleK = new Cle(a,nbBits);
		
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

		
		
		return cleK;
	}
	
	public static MessageEncrypte EncrypterElGamal (String m, Cle cleK){
		m = m.toUpperCase();

		Random rand = new SecureRandom();
		MessageEncrypte C = new MessageEncrypte();
		C.set_c("");
		BigInteger b = new BigInteger(cleK.get_nbBits(), rand);
		
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
		//Boucle parcourant le message lettre par lettre pour convertir en code ascii
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
		//Boucle parcourant le message lettre par lettre pour convertir en code ascii
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
				k = new BigInteger(cleK.get_nbBits() + 1, rand).add(BigInteger.ONE); 
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
		//Boucle parcourant le message lettre par lettre pour convertir en code ascii
		while (m.charAt(0) != "#".charAt(0)){
			charBuffer = m.charAt(0);
			m = m.substring(1);
			stringBuffer += (int)charBuffer;
		}
		
		M = new BigInteger(stringBuffer); //création du BigInteger contenant tous les codes ascii.
		//Calcul de H(M)
		hDeM = M.modPow(BigInteger.ONE.add(BigInteger.ONE), cleK.get_p());
		//On retourne ensuite le boolean correspondant à la vérification de la signature de la clé.
		return ( cleK.get_g().modPow(hDeM,cleK.get_p()).compareTo(((cleK.get_y().modPow(rs.get_r(),cleK.get_p())).multiply(rs.get_r().modPow(rs.get_s(),cleK.get_p()))).mod(cleK.get_p())) == 0 );
	}
	
 	public static void main(String[] args) {
 		Scanner sc = new Scanner(System.in);
		BigInteger a = BigInteger.ZERO;
		BigInteger g = BigInteger.ZERO;
		BigInteger p = BigInteger.ZERO;
		BigInteger y = BigInteger.ZERO;
		String C = "";
		BigInteger Y = BigInteger.ZERO;
		BigInteger s = BigInteger.ZERO;
		BigInteger r = BigInteger.ZERO;
		String message = "";
		boolean flag = true;
		MessageEncrypte messageEncrypte = new MessageEncrypte();
		MessageSigne messageSigne = new MessageSigne();
		int choix;
		
		//Le choix du nombre de bite va servir comme taille des nombres premiers aléatoires g et p.
		int nbBits;
		System.out.println("Bienvenue dans le programme ElGamal.");
		System.out.println("Veuillez indiquer le nombre de bit des nombres avec lesquels travailler :");
		//Boucle de récupération de l'entrée.
		while (true){
			System.out.print("Enter un chiffre entre un entier supérieur à 3 \n");
			if (!sc.hasNextInt()){
				sc.nextLine();
				System.out.println("Vous n'avez pas entré un chiffre.\n");
				continue;
			}
			nbBits = sc.nextInt();
			if (nbBits > 3){
				break;
			}
	    }
		Cle cleUtilisateur = new Cle(nbBits);
		
		//Boucle principale du programme.
		while (true){
			//Menu
			System.out.println("Quelle fonction voulez-vous tester ?");
			System.out.println("1-GenererClesElgamal");
			System.out.println("2-EncrypterElGamal");
			System.out.println("3-DecrypterElGamal");
			System.out.println("4-SignerElGamal");
			System.out.println("5-VerifierSignatureElGamal");
			System.out.println("6-Quitter le programme");
			
			//Boucle de récupération du choix du menu.
			while (true){
				System.out.print("Enter un chiffre entre 1 et 6 : \n");
				if (!sc.hasNextInt()){
					sc.nextLine();
					System.out.println("Vous n'avez pas entré un chiffre.\n");
					continue;
				}
				choix = sc.nextInt();
				if (choix < 7 && choix >0){
					sc.nextLine();
					break;
				}
		    }
			
			//Le switch permet d'executer la partie du programme correspondant au choix du menu.
			switch (choix){
				
				case 1: //Génération d'une clé
					cleUtilisateur = new Cle(nbBits); //remise à zero de l'objet
					System.out.println("Vous avez choisi de générer une clé. Merci d'entrer une clé secrète \"a\"qui doit être un entier supérieur à 0.");
					System.out.println("Ce programme utilisant la bibliothèque BigInteger, vous pouvez théoriquement entrer une clé secrète aussi grande que vous le voulez.");
					System.out.println("La seule limite sera la mémoire de votre machine");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("\nEnter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						a = sc.nextBigInteger();
						if (a.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
					//On appel la fonction de génération de clé
					cleUtilisateur = GenererClesElgamal(a,nbBits);
					System.out.println("Voici les paramètres générés :");
					System.out.println("a = " + cleUtilisateur.get_a().toString());
					System.out.println("g = " + cleUtilisateur.get_g().toString());
					System.out.println("q = " + cleUtilisateur.get_q().toString());
					System.out.println("p = 2*q+1 = " + cleUtilisateur.get_p().toString());
					System.out.println("y = g^a mod p = " + cleUtilisateur.get_y().toString() + "\n\n");
					break;
					
				case 2: //Encryption d'un message
					cleUtilisateur = new Cle(nbBits); //remise à zero de l'objet
					System.out.println("Vous avez choisi d'encrypter un message.");
					System.out.println("Merci d'entrer le message m à encrypter. Il peut être composé de lettres et de caractères d'espacement uniquement.");
					System.out.println("Ce programme utilisant la bibliothèque BigInteger, vous pouvez théoriquement entrer un message aussi grand que vous le voulez.");
					System.out.println("La seule limite sera la mémoire de votre machine");
					flag = true;
					//Boucle de récupération de l'entrée.
					while (flag){
						System.out.print("Merci d'entrer un message composé de lettre et de caractère d'espacement.\n");
						message = sc.nextLine();
						message = message.toUpperCase();
						flag = false;
						for (int i = 0; i<message.length(); i++){
							if (!(((int)message.charAt(i)) > 9 && ((int)message.charAt(i)) < 100)){
								flag = true;
							}
						}
				    }
					System.out.println("Merci d'entrer le générateur g :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						g = sc.nextBigInteger();
						if (g.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
					cleUtilisateur.set_g(g);
					System.out.println("Merci d'entrer le nombre premier p tel que p=2q+1 :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						p = sc.nextBigInteger();
						if (!p.isProbablePrime(200)){
							System.out.println("Vous n'avez pas entré un nombre premier.\n");
							continue;
						}
						if (p.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
					cleUtilisateur.set_p(p);
					System.out.println("Merci d'entrer le nombre y tel que y=g^a mod p :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0 et inférieur à p\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						y = sc.nextBigInteger();
						if (g.compareTo(BigInteger.ZERO) == 1 && g.compareTo(p) == -1){
							break;
						}
						else {
							System.out.println("Vous n'avez pas entré un nombre y supérieur à 0 et inférieur à p\n");
						}
				    }
					cleUtilisateur.set_y(y);
					//On appel ensuite la fonction d'encryption du message.
					messageEncrypte = EncrypterElGamal (message,cleUtilisateur);
					System.out.println("Voici le message encrypté :");
					System.out.println(messageEncrypte.get_c());
					System.out.println("Voici la valeur de Y = g^b mod p :");
					System.out.println(messageEncrypte.get_Y().toString()+ "\n\n");
					break;
					
					
				case 3: //Décryption d'un message
					cleUtilisateur = new Cle(nbBits); //remise à zero de l'objet
					System.out.println("Vous avez choisi de décrypter un message.");
					System.out.println("Merci d'entrer le message C à décrypter :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNext()){
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						else{
							C = sc.next();
							break;
						}
				    }
					messageEncrypte.set_c(C);
					
					System.out.println("Merci d'entrer Y = g^b mod p :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						Y = sc.nextBigInteger();
						if (Y.compareTo(BigInteger.ZERO) == 1){
							break;
						}
					}
					messageEncrypte.set_Y(Y);
					
					System.out.println("Merci d'entrée la clé secrète \"a\"");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						a = sc.nextBigInteger();
						if (a.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
					cleUtilisateur.set_a(a);
					
					System.out.println("Merci d'entrer le nombre premier p tel que p=2q+1 :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						p = sc.nextBigInteger();
						if (!p.isProbablePrime(200)){
							System.out.println("Vous n'avez pas entré un nombre premier.\n");
							continue;
						}
						if (p.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
					cleUtilisateur.set_p(p);
					
					System.out.println("Merci d'entrer le générateur g :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						g = sc.nextBigInteger();
						if (g.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
					cleUtilisateur.set_g(g);
					
					//Appel de la fonction d'encryption du message
					message = DecrypterElGamal (messageEncrypte,cleUtilisateur);
					System.out.println("Voici le message décrypté :");
					System.out.println(message + "\n\n");
					break;
					
				case 4: //Signature d'un message
					cleUtilisateur = new Cle(nbBits); //remise à zero de l'objet
					System.out.println("Vous avez choisi de signer un message.");
					System.out.println("Merci d'entrer le message m à encrypter. Il peut être uniquement composé de lettres et de caractères d'espacement.");
					System.out.println("Ce programme utilisant la bibliothèque BigInteger, vous pouvez théoriquement entrer un message aussi grand que vous le voulez.");
					System.out.println("La seule limite sera la mémoire de votre machine");
					flag = true;
					//Boucle de récupération de l'entrée.
					while (flag){
						System.out.print("Merci d'entrer un message composé de lettre et de caractère d'espacement.\n");
						message = sc.next();
						message = message.toUpperCase();
						flag = false;
						for (int i = 0; i<message.length(); i++){
							if (!(((int)message.charAt(i)) > 9 && ((int)message.charAt(i)) < 100)){
								flag = true;
							}
						}
				    };
				    
				    System.out.println(" Merci d'entrer la clé secrète \"a\" doit être un entier supérieur à 0.");
					while (true){
						System.out.print("\nEnter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						a = sc.nextBigInteger();
						if (a.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
				    cleUtilisateur.set_a(a);
				    
				    System.out.println("Merci d'entrer le générateur g :");
				  //Boucle de récupération de l'entrée.
				    while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						g = sc.nextBigInteger();
						if (g.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
					cleUtilisateur.set_g(g);
					
					System.out.println("Merci d'entrer le nombre premier p tel que p=2q+1 :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						p = sc.nextBigInteger();
						if (!p.isProbablePrime(200)){
							System.out.println("Vous n'avez pas entré un nombre premier.\n");
							continue;
						}
						if (p.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
					cleUtilisateur.set_p(p);
					
					System.out.println("Merci d'entrer le nombre y tel que y=g^a mod p :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0 et inférieur à p\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						y = sc.nextBigInteger();
						if (y.compareTo(BigInteger.ZERO) == 1){
							break;
						}
						else {
							System.out.println("Vous n'avez pas entré un nombre y supérieur à 0 et inférieur à p\n");
						}
				    }
					cleUtilisateur.set_y(y);
				    
					//Appel de la fonction de signature
					messageSigne = SignerElGamal(message,cleUtilisateur);
				    System.out.println("Voici le message signé :");
					System.out.println(messageSigne.get_s().toString());
					System.out.println("Voici la valeur de r = g^k mod p :");
					System.out.println(messageSigne.get_r().toString()+ "\n\n");
					break;
					
				case 5: //Vérification de la signature d'un message
					cleUtilisateur = new Cle(nbBits);
					System.out.println("Vous avez choisi de vérifier une signature");
					System.out.println("Merci d'entrer le message m à vérifier");
					flag = true;
					//Boucle de récupération de l'entrée.
					while (flag){
						System.out.print("Merci d'entrer un message composé de lettre et de caractère d'espacement.\n");
						message = sc.next();
						message = message.toUpperCase();
						flag = false;
						for (int i = 0; i<message.length(); i++){
							if (!(((int)message.charAt(i)) > 9 && ((int)message.charAt(i)) < 100)){
								flag = true;
							}
						}
				    };
				    
				    System.out.println("Merci le paramètre \"s\" de la signature :");
				    //Boucle de récupération de l'entrée.
				    while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						s = sc.nextBigInteger();
						if (s.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
					messageSigne.set_s(s);
					
					System.out.println("Merci le paramètre \"r\" de la signature :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						r = sc.nextBigInteger();
						if (r.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
					messageSigne.set_r(r);
				    
					System.out.println("Merci d'entrer le générateur g :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						g = sc.nextBigInteger();
						if (g.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
					cleUtilisateur.set_g(g);
					
					System.out.println("Merci d'entrer le nombre premier p tel que p=2q+1 :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						p = sc.nextBigInteger();
						if (!p.isProbablePrime(200)){
							System.out.println("Vous n'avez pas entré un nombre premier.\n");
							continue;
						}
						if (p.compareTo(BigInteger.ZERO) == 1){
							break;
						}
				    }
					cleUtilisateur.set_p(p);
					
					System.out.println("Merci d'entrer le nombre y tel que y=g^a mod p :");
					//Boucle de récupération de l'entrée.
					while (true){
						System.out.print("Enter un entier supérieur à 0 et inférieur à p\n");
						if (!sc.hasNextBigInteger()){
							sc.nextLine();
							System.out.println("Vous n'avez pas entré un nombre entier\n");
							continue;
						}
						y = sc.nextBigInteger();
						if (y.compareTo(BigInteger.ZERO) == 1 ){
							break;
						}
						else {
							System.out.println("Vous n'avez pas entré un nombre y supérieur à 0 et inférieur à p\n");
						}
				    }
					cleUtilisateur.set_y(y);
					
					if(VerifierSignatureElGamal (message, messageSigne, cleUtilisateur)){
						System.out.println("La signature est correcte");
					}
					else{
						System.out.println("La signature est incorrecte");
					}
					break;
					
				case 6: 
					sc.close();
					System.exit(0);
					break;
			}
		}
	}
}
