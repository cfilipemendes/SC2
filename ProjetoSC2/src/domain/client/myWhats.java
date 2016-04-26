package domain.client;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class myWhats {

	private static Scanner sc;
	private static Socket soc;
	private static ObjectInputStream in;
	private static ObjectOutputStream out;
	private static final String flags = "-p-m-f-r-a-d";
	private static final Pattern PATTERN = Pattern.compile(
			"^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
	private final static int SALT_ERROR = -64;
	private final static int CHAR_ERROR = -65;
	private final static int PW_ERROR = -66;
	private final static int ARGS_ERROR = -67;
	private final static int REG_ERROR = -68;
	private final static int PACKET_SIZE = 1024;
	private static String pwd;
	private static byte[] ciphAux;
	private static Cipher cAES;
	private static MessageDigest md;

	public static void main (String [] args) throws UnknownHostException, IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, KeyStoreException, CertificateException, UnrecoverableKeyException{

		if (args.length < 2){
			System.err.println(Errors.errorConfirm(-2));
			return;
		}
		else if (args.length > 2)
			if (!flags.contains(args[2])){
				System.err.println(Errors.errorConfirm(-3));
				return;
			}

		if (args.length > 7)
			System.err.println(Errors.errorConfirm(-4));

		String userName = args[0];
		String ip = args[1].split(":")[0];
		String port = args[1].split(":")[1];
		//verifica se o IP eh vahlido!
		if (!validIP(ip)){
			System.err.println("IP invalido");
			return;
		}

		int valid = Errors.validate(args);
		if (valid != 1 && valid != -10){
			verifyInput(valid);
			return;
		}

		sc = new Scanner (System.in);

		pwd = null;
		if (valid == -10)
			pwd = retryPwd(sc);

		//guarda a key
		System.setProperty("javax.net.ssl.trustStore", "myClient.keyStore");

		//Ligacao socket

		SocketFactory sf = SSLSocketFactory.getDefault( );
		soc = sf.createSocket(ip, Integer.parseInt(port));

		//Abertura das Streams
		in = new ObjectInputStream(soc.getInputStream());
		out = new ObjectOutputStream(soc.getOutputStream());

		//Modelizacao do array de envio ao servidor!
		String [] argsFinal;
		if (pwd != null){
			argsFinal = new String [args.length-2];
			int x = 2;
			for (int i = 0; i < argsFinal.length; i++){
				argsFinal[i] = args[x];
				x++;
			}
		}
		else{
			argsFinal = new String [args.length-4];
			pwd=args[3];
			int x = 4;
			for (int i = 0; i < argsFinal.length; i++){
				argsFinal[i] = args[x];
				x++;
			}
		}

		//gerar uma cifra simetrica
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(128);
		SecretKey key = kg.generateKey();

		//wrap da publicK na key
		Cipher cWrap = Cipher.getInstance("RSA");	

		cAES = Cipher.getInstance("AES");
		cAES.init(Cipher.ENCRYPT_MODE, key);


		//envia o username cifrado
		out.writeObject(userName);

		int salt = (int)in.readObject();

		//Se nao existir user cria salt
		if (salt == SALT_ERROR){
			Random random = new Random();
			salt = random.nextInt(1000000);
			//envia o salt
			out.writeObject(salt);
		}

		//adiciona salt a password
		String saltStr = Integer.toString(salt);
		if (saltStr.length() < 6)
			saltStr = addZerosSalt(saltStr);
		String pwdSalt = pwd.concat(":"+saltStr);

		//cria o hash
		md = MessageDigest.getInstance("SHA-256");
		byte buf[] = pwdSalt.getBytes();
		byte hash[] = md.digest(buf);
		String pwdHash = new String (hash);
		out.writeObject(pwdHash);

		int fromServer = (int) in.readObject();
		int tries = 2;
		while(fromServer == PW_ERROR){
			if (tries == 0){
				System.err.print("Password ERRADA! Acabaram-se as tentativas");
				closeCon();
				return;
			}
			System.err.print("Password ERRADA!\nTem " + tries + " tentativa(s)!\n");
			tries --;
			pwdHash = retryPwd(sc,saltStr);
			out.writeObject(pwdHash);
			fromServer = (int) in.readObject();
		}
		if (fromServer == CHAR_ERROR){
			System.err.println(Errors.errorConfirm(CHAR_ERROR));
			closeCon();
			return;
		}
		if (fromServer == REG_ERROR){
			System.err.println(Errors.errorConfirm(REG_ERROR));
			closeCon();
			return;
		}


		//Cria uma keystore e vai buscar a private key do user e inicia a cipher unwrap
		FileInputStream kfile = new FileInputStream(userName + ".keyStore");
		KeyStore kstore = KeyStore.getInstance("JKS");
		kstore.load(kfile,pwd.toCharArray());
		PrivateKey privateKey = (PrivateKey) kstore.getKey(userName,pwd.toCharArray());
		Cipher cUnwrap = Cipher.getInstance("RSA");
		cUnwrap.init(Cipher.UNWRAP_MODE, privateKey);


		///////////////////////////////////////////////////////////////////
		//////////////////ACABOU O REGISTO E AUTENTICACAO//////////////////
		///////////////////////////////////////////////////////////////////
		/////////////////COMECOU A TRANSFERENCIA DE DADOS//////////////////
		///////////////////////////////////////////////////////////////////

		//envia o numero de argumentos
		out.writeObject(argsFinal.length);

		int x;
		Certificate cert;
		String [] groupUsers = null;
		//envia todos os argumentos
		for (int i = 0; i < argsFinal.length; i++){
			//encriptar a mensagem com a cifra assimetrica
			if (argsFinal[0].equals("-m") || argsFinal[0].equals("-f")){
				if (i == 0){
					out.writeObject(argsFinal[i]);
				}
				else if (i == 1) {
					out.writeObject(argsFinal[i]);
					x = (int) in.readObject();
					if (x != 1){
						System.err.println(Errors.errorConfirm(x));
						return;
					}
					groupUsers = (String []) in.readObject();
				}
				else if (i == 2 && argsFinal[0].equals("-m")){
					//envia a sig
					ciphAux = md.digest(argsFinal[2].getBytes());
					out.writeObject(ciphAux);
					//envia a mensagem cifrada
					ciphAux = cAES.doFinal(argsFinal[2].getBytes());
					out.writeObject(ciphAux);

					x = (int) in.readObject();
					if (x != 1){
						System.err.println(Errors.errorConfirm(x));
						return;
					}

					for(int j = 0; j<groupUsers.length;j++){
						cert = kstore.getCertificate(groupUsers[j]);
						cWrap.init(Cipher.WRAP_MODE, cert);
						ciphAux = cWrap.wrap(key);
						out.writeObject(ciphAux);
					}
				}

				else if (i == 2 && argsFinal[0].equals("-f")){
					out.writeObject(argsFinal[i]);
				}
			}
			else{
				out.writeObject(argsFinal[i]);
			}
		}

		//verifica se os dados foram bem recebidos pelo servidor
		fromServer = (int) in.readObject();
		if (fromServer == ARGS_ERROR){
			System.err.println(Errors.errorConfirm(ARGS_ERROR));
			closeCon();
			return;
		}

		//envio de ficheiro
		if(argsFinal.length >= 1){
			if (argsFinal[0].equals("-f")){

				File myFile = new File (argsFinal [2]);
				if (!myFile.exists() || myFile.isDirectory()){
					out.writeObject(-1);
					System.err.println(Errors.errorConfirm(-11));
					closeCon();
					return;
				}

				if (argsFinal[2].startsWith("\\.") || argsFinal[2].contains("-") || argsFinal[2].contains("/") || argsFinal[2].contains("_")){
					out.writeObject(-1);
					System.err.println(Errors.errorConfirm(-12));
					closeCon();
					return;
				}
				//se nao ocorrer erro nenhum
				out.writeObject(1);

				FileInputStream fisSig = new FileInputStream (myFile);
				byte [] byteArraySig = new byte [(int)myFile.length()];
				fisSig.read(byteArraySig);
				fisSig.close();
				ciphAux = md.digest(byteArraySig);
				out.writeObject(ciphAux);

				File fileAux = new File (argsFinal[2] + ".ciph");
				cipherFile(myFile, fileAux, cAES);
				int fileSize = (int) fileAux.length();
				byte [] byteArray = new byte [fileSize];
				FileInputStream fis = new FileInputStream (fileAux);
				BufferedInputStream bis = new BufferedInputStream (fis);
				int bytesRead;
				int current = 0; 

				out.writeObject(fileSize);

				int nCiclo = fileSize/PACKET_SIZE;
				int resto = fileSize%PACKET_SIZE;

				for (int i = 0; i < nCiclo; i++){
					bytesRead = bis.read(byteArray,current,PACKET_SIZE);
					out.write(byteArray,current,bytesRead);
					out.flush();
					if (bytesRead > 0)
						current += bytesRead;
				}
				if (resto > 0){
					bytesRead = bis.read(byteArray,current,resto);
					out.write(byteArray,current,bytesRead);
					out.flush();
				}

				//Envia as keys simetricas ao servidor 
				for(int j = 0; j<groupUsers.length;j++){
					cert = kstore.getCertificate(groupUsers[j]);
					cWrap.init(Cipher.WRAP_MODE, cert.getPublicKey());
					ciphAux = cWrap.wrap(key);
					out.writeObject(ciphAux);
				}

				bis.close();
				fis.close();

				fileAux.delete();
			}

			//recepcao de ficheiros
			else if (argsFinal[0].equals("-r")){
				int check;
				//  -r contacto file
				if(argsFinal.length == 3){
					check = (int)in.readObject();
					if (check != 1){
						return;
					}
					check = getFileFromServer(argsFinal[2],in,cUnwrap);
					if (check != 1){
						System.err.println(Errors.errorConfirm(check));
						closeCon();
						return;
					}
				}
				// -r contacto ultima mensagem
				else if(argsFinal.length == 2){
					check = (int)in.readObject();
					if (check != 1){
						System.err.println(Errors.errorConfirm(check));
						return;
					}
					check = getContactConv(in, userName,cUnwrap);
					if (check != 1){
						System.err.println(Errors.errorConfirm(check));
						closeCon();
						return;
					}
				}
				// -r que recebe tudo
				else if(argsFinal.length == 1){
					check = getLatestConvs(in,userName,cUnwrap);
					if (check != 1){
						System.err.println(Errors.errorConfirm(check));
						closeCon();
						return;
					}
				}
			}
		}
		int confirm = (int) in.readObject();
		System.err.println(Errors.errorConfirm(confirm));
		closeCon();
	}



	// ----------------------  FIM DO MAIN -----------------------------
	// -----------------------------------------------------------------
	//------------------------------------------------------------------
	//------------------------------------------------------------------
	//------------------------------------------------------------------
	/**
	 * recebe do servidor a ultima conversa que o utilizador teve com 
	 * todos os seus contactos e grupos
	 * @param in stream pela qual vai acontecer a comunicacao servidor cliente
	 * @param userName nome do utilizador que esta a pedir as conversas
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	private static int getLatestConvs(ObjectInputStream in, String userName, Cipher cUnwrap) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException {
		try {
			Key secKey;
			byte [] deciphMsg,sig, hash;
			//numero de contactos que o utilizador tem
			int nContacts = (int) in.readObject();
			String [] receivedC;
			for(int i = 0; i < nContacts; i++){
				//recebe a mensagem cifrada
				receivedC = (String[]) in.readObject();

				if (receivedC == null)
					return -14;

				//Se for messagem
				if (receivedC[4].equals("-m")){
					byte [] messCifrada = (byte[]) in.readObject();

					//recebe a chave cifrada
					int sizerino = (int) in.readObject();
					DataInputStream dis = new DataInputStream(in);
					byte [] ciphAux2 = new byte [sizerino];
					dis.readFully(ciphAux2);

					secKey = cUnwrap.unwrap(ciphAux2, "AES", Cipher.SECRET_KEY);

					//decifra a mensagem
					cAES.init(Cipher.DECRYPT_MODE, secKey);
					deciphMsg = cAES.doFinal(messCifrada);

					//cria o hash
					hash = md.digest(deciphMsg);

					//recebe a sig e verifica a sua integridade
					sig = (byte []) in.readObject();
					if (!MessageDigest.isEqual(sig, hash)){
						return -13;
					}
					receivedC[3] = new String (deciphMsg);
				}

				printR0 (receivedC,userName,false);
			}
			//numero de grupos que o utilizador pertence
			int nGroups = (int) in.readObject();
			String [] receivedU;
			for(int i = 0; i < nGroups; i++){
				receivedU = (String[]) in.readObject();
				if (receivedU == null)
					return -14;

				//Se for messagem
				if (receivedU[4].equals("-m")){
					byte [] messCifrada = (byte[]) in.readObject();

					//recebe a chave cifrada
					int sizerino = (int) in.readObject();
					DataInputStream dis = new DataInputStream(in);
					byte [] ciphAux2 = new byte [sizerino];
					dis.readFully(ciphAux2);

					secKey = cUnwrap.unwrap(ciphAux2, "AES", Cipher.SECRET_KEY);

					//decifra a mensagem
					cAES.init(Cipher.DECRYPT_MODE, secKey);
					deciphMsg = cAES.doFinal(messCifrada);

					//cria o hash
					hash = md.digest(deciphMsg);

					//recebe a sig e verifica a sua integridade
					sig = (byte []) in.readObject();
					if (!MessageDigest.isEqual(sig, hash)){
						return -13;
					}
					receivedU[3] = new String (deciphMsg);
				}
				printR0 (receivedU,userName,true);
			}
		} catch (ClassNotFoundException | IOException e) {
			e.printStackTrace();
		}
		return 1;
	}

	/**
	 * recebe do servidor a conversa completa que o utilizador teve com outro
	 * contacto
	 * @param inStream stream pela qual vai acontecer a comunicacao servidor cliente
	 * @param userName nome do utilizador
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	private static int getContactConv(ObjectInputStream inStream, String userName, Cipher cUnwrap) throws InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
		try {
			Key secKey;
			byte [] sig, deciphMsg, hash;
			int nFile = (int) inStream.readObject();
			String [] received;
			for (int i = 0; i < nFile; i++){
				received = (String[]) inStream.readObject();
				if (received != null){
					
					//Se for messagem
					if (received[4].equals("-m")){
						byte [] messCifrada = (byte[]) in.readObject();

						//recebe a chave cifrada
						int sizerino = (int) in.readObject();
						DataInputStream dis = new DataInputStream(in);
						byte [] ciphAux2 = new byte [sizerino];
						dis.readFully(ciphAux2);

						secKey = cUnwrap.unwrap(ciphAux2, "AES", Cipher.SECRET_KEY);

						//decifra a mensagem
						cAES.init(Cipher.DECRYPT_MODE, secKey);
						deciphMsg = cAES.doFinal(messCifrada);

						//cria o hash
						hash = md.digest(deciphMsg);

						//recebe a sig e verifica a sua integridade
						sig = (byte []) in.readObject();
						if (!MessageDigest.isEqual(sig, hash)){
							return -13;
						}
						received[3] = new String (deciphMsg);
					}

					printR1 (received,userName);
				}
			}
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return 1;
	}

	/**
	 * recebe um ficheiro do servidor
	 * @param fich nome do ficheiro a ser recebido do servidor
	 * @param inStream stream pela qual vai acontecer a comunicacao servidor cliente
	 */
	private static int getFileFromServer(String fich, ObjectInputStream inStream, Cipher cUnwrap) {
		try {
			Key secKey;
			byte [] hash,sig;
			int fileSize = (int) inStream.readObject();
			if (fileSize < 0){
				return -15;
			}
			byte [] byteArray = new byte [fileSize];
			FileOutputStream fileAux = new FileOutputStream(new File(".").getAbsolutePath() + "//" + fich + ".ciph");
			BufferedOutputStream bosFrom = new BufferedOutputStream(fileAux);

			int current = 0;
			int bytesRead;
			int nCiclo = fileSize/PACKET_SIZE;
			int resto = fileSize%PACKET_SIZE;

			for (int i = 0; i < nCiclo; i++){
				bytesRead = inStream.read(byteArray, current,PACKET_SIZE);
				bosFrom.write(byteArray,current,bytesRead);
				bosFrom.flush();
				if (bytesRead > 0)
					current += bytesRead;
			}

			if (resto > 0){
				bytesRead = inStream.read(byteArray, current,resto);
				bosFrom.write(byteArray,current,bytesRead);
				bosFrom.flush();
			}
			bosFrom.close();
			fileAux.close();
			
			//recebe a chave cifrada
			int sizerino = (int) in.readObject();
			DataInputStream dis = new DataInputStream(in);
			byte [] ciphAux2 = new byte [sizerino];
			dis.readFully(ciphAux2);
			//decifra a chave
			secKey = cUnwrap.unwrap(ciphAux2, "AES", Cipher.SECRET_KEY);
			
			
			
			/////////////////Esta aqui o problema!!!!!!!!!!!!!!////////////////////////
			//decifra o ficheiro
			File myFile = new File (new File(".").getAbsolutePath() + "//" + fich);
			File fileAux1 = new File (new File(".").getAbsolutePath() + "//" + fich + ".ciph");
			cAES.init(Cipher.DECRYPT_MODE, secKey);
			cipherFile(fileAux1, myFile, cAES);
			
			//depois de decifrado apaga o ficheiro cifrado do cliente
			fileAux1.delete();
			
			FileInputStream fisSig = new FileInputStream (myFile);
			byte [] byteArraySig = new byte [(int)myFile.length()];
			fisSig.read(byteArraySig);
			fisSig.close();
			
			//cria o hash
			hash = md.digest(byteArraySig);
			
			//recebe a sig e verifica a sua integridade
			sig = (byte []) in.readObject();
			if (!MessageDigest.isEqual(sig, hash)){
				return -13;
			}

			
		} catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return 1;

	}

	/**
	 * fecha a ligacao com as streams in e out com o scanner sc
	 * e com a socket soc
	 */
	private static void closeCon (){
		try {
			out.close();
			in.close();
			sc.close();
			soc.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * pede ao cliente a password novamente
	 * @param sc Scanner por onde vai passar o input
	 * @return uma tentativa de password
	 */
	private static String retryPwd(Scanner sc){
		System.out.println("Por favor insira a PASSWORD:");
		String pwd = null;
		pwd = sc.nextLine();
		return pwd;
	}

	private static String retryPwd(Scanner sc2, String saltStr) throws NoSuchAlgorithmException {
		System.out.println("Por favor insira a PASSWORD:");
		pwd = sc.nextLine();
		String pwdSalt = pwd.concat(":"+saltStr);

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte buf[] = pwdSalt.getBytes();
		byte hash[] = md.digest(buf);
		return new String (hash);
	}

	/**
	 * imprime na consola o tipo de erro que sucedeu com o input
	 * @param fromServer int com o tipo de erro a ser decodificado
	 */
	private static void verifyInput(int fromServer) {
		switch(fromServer){
		case -1:
			System.out.println("Argumentos recebidos a null!");
			break;
		case -2:
			System.out.println("Ordem da flag -p invalida");
			break;
		case -3:
			System.out.println("Argumento da pass e uma flag!");
			break;
		case -4:
			System.out.println("Argumentos insuficientes para a password!");
			break;
		case -5:
			System.out.println("Flag invalida a seguir ao -p!");
			break;
		case -6:
			System.out.println("Ordem errada das flags");
			break;
		case -7:
			System.out.println("Argumentos das flags invalidos!");
			break;
		}

	}

	/**
	 * verifica se o endereco ip eh valido
	 * @param ip endereco a ser testado
	 * @return boolean true se o endereco ip for valido
	 */
	//Verifica o IP dado pelo utilizador
	public static boolean validIP(final String ip) {
		return PATTERN.matcher(ip).matches();
	}

	/**
	 * imprime no cliente o -r com 1 argumentos
	 * @param received nome dos ficheiros e data
	 * @param userName nome do utilizador
	 */
	private static void printR1(String[] received, String userName) {
		StringBuilder sb = new StringBuilder ();
		if (!received[0].equals(userName))
			sb.append(received[0] + ": " + received[3] + "\n");
		else
			sb.append("me: " + received[3] + "\n");
		String[] data = received[2].split("_");
		if (data[1].contains(".")){
			String [] horaAux = data[1].split("\\.");
			String [] hora = horaAux[0].split("-");
			sb.append(data[0] + " " + hora[0] + ":" + hora[1]);
		}
		else{
			String [] hora = data[1].split("-");
			sb.append(data[0] + " " + hora[0] + ":" + hora[1]);
		}
		System.out.println(sb.toString());
	}

	/**
	 * imprime na consola do cliente o -r com 0 argumentos
	 * @param received nome dos ficheiros e data
	 * @param userName nome do utilizador
	 * @param group boolean para diferenciar a impressao, true se for para um grupo ou false se for para um utilizador
	 */
	private static void printR0(String[] received, String userName,boolean group) {
		if (group)
			System.out.println("Contact: " + received[1]);
		else{
			if (received[0].equals(userName))
				System.out.println("Contact: " + received[1]);
			else
				System.out.println("Contact: " + received[0]);
		}
		printR1(received,userName);
	}

	private static String addZerosSalt (String num) {
		String z = "0";
		int numZeros = 6 - num.length();
		for(int i = 1; i < numZeros; i++){
			z.concat("0");
		}
		return z.concat(num);
	}

	private static void cipherFile(File myFile,File fileAux, Cipher cAES) throws IOException {
		FileInputStream is = new FileInputStream(myFile);
		CipherOutputStream os = new CipherOutputStream(new FileOutputStream(fileAux), cAES);

		copy(is, os);
	}



	private static void copy(FileInputStream is, CipherOutputStream os) throws IOException {
		int i;
		byte[] b = new byte[1024];
		while((i=is.read(b))!=-1) {
			os.write(b, 0, i);
		}
	}
}

