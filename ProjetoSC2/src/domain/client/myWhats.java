package domain.client;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
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
	private final static int CHAR_ERROR = -65;
	private final static int PW_ERROR = -66;
	private final static int ARGS_ERROR = -67;
	private final static int REG_ERROR = -68;
	private final static int PACKET_SIZE = 1024;


	public static void main (String [] args) throws UnknownHostException, IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

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

		String pwd = null;
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

		//gerar uma chave aleatória para utilizar com o AES
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(128);
		SecretKey key = kg.generateKey();

		//gerar uma cifra assimetrica
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048); //2048 bits
		KeyPair kp = kpg.generateKeyPair( );
		PublicKey publicK = kp.getPublic();
		PrivateKey privateK = kp.getPrivate();
		
		//chave publica do cliente em array de bytes
		byte[]keyEncoded;

		//recebe a chave publica do servidor
		PublicKey servPubK = (PublicKey) in.readObject();

		//wrap da publicK na key
		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.WRAP_MODE, servPubK);
		byte [] wrapKey = c.wrap(key);		

		c = Cipher.getInstance("AES");
		c.init(Cipher.ENCRYPT_MODE, key);

		byte[] ciphAux = c.doFinal(userName.getBytes());

		//envia o username
		out.writeObject(wrapKey);
		out.writeObject(ciphAux);

		ciphAux = c.doFinal(pwd.getBytes());

		out.writeObject(ciphAux);

		File fAux = new File (new File(".").getAbsolutePath() + "//" + userName + "Private.key");

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
			pwd = retryPwd(sc);
			ciphAux = c.doFinal(pwd.getBytes());
			out.writeObject(ciphAux);
			fromServer = (int) in.readObject();
			if (fromServer == 56){
				out.writeObject(publicK);
				FileOutputStream fos = new FileOutputStream (new File(".").getAbsolutePath() + "//" + userName + "Private.key");
				ObjectOutputStream oos = new ObjectOutputStream(fos);
				oos.writeObject(privateK);
				oos.close();
			}
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
		//Se o server for criar o utilizador pela primeira vez
		//ou se nao tiver a public key guardada
		//ou se o cliente nao tiver a private key guardada
		boolean temp=false;
		if (fromServer == 55 || fromServer == 56 || (temp=!fAux.exists())){
			if (temp)
				out.writeObject(57);//informa o servidor que vai enviar uma publickey do cliente
			out.writeObject(publicK);
			FileOutputStream fos = new FileOutputStream (new File(".").getAbsolutePath() + "//" + userName + "Private.key");
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(privateK);
			oos.close();
		}
		else if (fromServer == 58){
			keyEncoded = (byte[]) in.readObject();
		}
		if(!temp)
			//correu tudo bem com a autenticacao no cliente
			out.writeObject(1);
	

		
		
		///////////////////////////////////////////////////////////////////
		//////////////////ACABOU O REGISTO E AUTENTICACAO//////////////////
		///////////////////////////////////////////////////////////////////
		/////////////////COMECOU A TRANSFERENCIA DE DADOS//////////////////
		///////////////////////////////////////////////////////////////////
		
		
		
		//envia o numero de argumentos
		ciphAux = c.doFinal(Integer.toString(argsFinal.length).getBytes());
		out.writeObject(ciphAux);
		//envia todos os argumentos
		for (int i = 0; i < argsFinal.length; i++){
			//encriptar a mensagem com a cifra assimetrica
			if (argsFinal[0] == "-m" && i == 2){

			}
			ciphAux = c.doFinal(argsFinal[i].getBytes());
			out.writeObject(ciphAux);
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
				if (argsFinal[2].startsWith("\\.") || argsFinal[2].contains("-") || argsFinal[2].contains("/") || argsFinal[2].contains("_")){
					out.writeObject(-1);
					System.err.println(Errors.errorConfirm(-12));
					closeCon();
					return;
				}
				File myFile = new File (argsFinal [2]);
				if (!myFile.exists() || myFile.isDirectory()){
					out.writeObject(-1);
					System.err.println(Errors.errorConfirm(-11));
					closeCon();
					return;
				}
				int fileSize = (int) myFile.length();
				byte [] byteArray = new byte [fileSize];
				FileInputStream fis = new FileInputStream (myFile);
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

				bis.close();
				fis.close();

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
					getFileFromServer(argsFinal[2],in);
				}
				// -r contacto ultima mensagem
				else if(argsFinal.length == 2){
					check = (int)in.readObject();
					if (check != 1){
						System.err.println(Errors.errorConfirm(check));
						return;
					}
					getContactConv(in, userName);
				}
				// -r que recebe tudo
				else if(argsFinal.length == 1){
					getLatestConvs(in,userName);
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
	 */
	private static void getLatestConvs(ObjectInputStream in, String userName) {
		try {
			//numero de contactos que o utilizador tem
			int nContacts = (int) in.readObject();
			String [] receivedC;
			for(int i = 0; i < nContacts; i++){
				receivedC = (String[]) in.readObject();
				if (receivedC != null)
					printR0 (receivedC,userName,false);
			}
			//numero de grupos que o utilizador pertence
			int nGroups = (int) in.readObject();
			String [] receivedU;
			for(int i = 0; i < nGroups; i++){
				receivedU = (String[]) in.readObject();
				if (receivedU != null)
					printR0 (receivedU,userName,true);
			}
		} catch (ClassNotFoundException | IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * recebe do servidor a conversa completa que o utilizador teve com outro
	 * contacto
	 * @param inStream stream pela qual vai acontecer a comunicacao servidor cliente
	 * @param userName nome do utilizador
	 */
	private static void getContactConv(ObjectInputStream inStream, String userName) {
		try {
			int nFile = (int) inStream.readObject();
			String [] received;
			for (int i = 0; i < nFile; i++){
				received = (String[]) inStream.readObject();
				if (received != null)
					printR1 (received,userName);
			}
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * recebe um ficheiro do servidor
	 * @param fich nome do ficheiro a ser recebido do servidor
	 * @param inStream stream pela qual vai acontecer a comunicacao servidor cliente
	 */
	private static void getFileFromServer(String fich, ObjectInputStream inStream) {
		try {
			int fileSize = (int) inStream.readObject();
			if (fileSize < 0){
				return;
			}
			byte [] byteArray = new byte [fileSize];
			FileOutputStream fosFrom = new FileOutputStream(new File(".").getAbsolutePath() + 
					"//" + fich);
			BufferedOutputStream bosFrom = new BufferedOutputStream(fosFrom);

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
			fosFrom.close();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

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
			sb.append(received[0] + ": " + received[3]);
		else
			sb.append("me: " + received[3]);//oi
		String[] data = received[2].split("_");
		if (data[1].contains(".")){
			String [] horaAux = data[1].split("\\.");
			String [] hora = horaAux[0].split("-");
			sb.append(data[0] + " " + hora[0] + ":" + hora[1]);
		}
		else{
			String [] hora = data[1].split("-");
			sb.append("\n" + data[0] + " " + hora[0] + ":" + hora[1]);
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
}
