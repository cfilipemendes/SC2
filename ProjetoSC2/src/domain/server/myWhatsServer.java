package domain.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;


/***************************************************************************
 *  
 *
 *
 ***************************************************************************/

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

//Servidor do servico myWhatsServer

public class myWhatsServer {

	private final String USERS_PWS_FILE = "usersAndPws";
	private final String GROUPS_DIR = "groups";
	private final String USERS_DIR = "users";
	private final String KEYS_DIR = "keys";
	private final int SALT_ERROR = -64;
	private final int CHAR_ERROR = -65;
	private final int PW_ERROR = -66;
	private final int ARGS_ERROR = -67;
	private final int REG_ERROR = -68;
	private server_skell skell;
	private String pwdMac;
	private final static String ksPwd = "littlestars"; 


	public static void main(String[] args) {
		myWhatsServer server = new myWhatsServer();
		server.startServer(Integer.parseInt(args[0]));
	}

	public void startServer (int port){
		ServerSocket ss = null;

		System.setProperty("javax.net.ssl.keyStore", "myServer.keystore");
		System.setProperty("javax.net.ssl.keyStorePassword", "littlestars");

		//Fazer isto!!!!!!
		System.out.println("Qual a password para o MAC?");

		Scanner sc = new Scanner (System.in);
		pwdMac = sc.nextLine();
		sc.close();



		try {
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault( );
			ss = ssf.createServerSocket(port);
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		//cria um skell do servidor
		skell = new server_skell(USERS_PWS_FILE,GROUPS_DIR, USERS_DIR, KEYS_DIR);

		while(true) {
			try {
				Socket inSoc = ss.accept();
				ServerThread newServerThread = new ServerThread(inSoc,skell);
				newServerThread.start();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		}
		//sSoc.close();
	}


	//Threads utilizadas para comunicao com os clientes
	class ServerThread extends Thread {

		private Socket socket = null;
		private server_skell skell;
		ObjectOutputStream outStream;
		ObjectInputStream inStream;

		ServerThread(Socket inSoc, server_skell skell) {
			socket = inSoc;
			this.skell = skell;
		}

		public void run(){
			try {
				outStream = new ObjectOutputStream(socket.getOutputStream());
				inStream = new ObjectInputStream(socket.getInputStream());
				int numArgs;
				int confirm;
				byte [] ciphuserName;
				String username;
				byte[] ciphpwd;
				String password;
				byte [] wrapKey;
				SecretKey key;
				byte [] ciphAux;
				byte [] deciphAux;
				try {

					byte [] pwdMacByte = pwdMac.getBytes();
					SecretKey keyMac = new SecretKeySpec(pwdMacByte, "HmacSHA256");

					Mac m;
					byte[]mac=null;
					m = Mac.getInstance("HmacSHA256");
					m.init(keyMac);
					m.update(pwdMacByte);
					mac = m.doFinal();

					//Cria uma cifra assimetrica
					KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
					kpg.initialize(2048); //2048 bits
					KeyPair kp = kpg.generateKeyPair( );
					PublicKey publicK = kp.getPublic();
					PrivateKey privateK = kp.getPrivate();

					//envia ao cliente a chave publica
					outStream.writeObject(publicK);

					//recebe a key do cliente cifrada com a publicK do servidor
					wrapKey = (byte[]) inStream.readObject();

					Cipher c = Cipher.getInstance("RSA");
					c.init(Cipher.UNWRAP_MODE, privateK);
					key = (SecretKey) c.unwrap(wrapKey, "AES", Cipher.SECRET_KEY);

					//recebe o username cifrado
					ciphuserName = (byte []) inStream.readObject();

					c = Cipher.getInstance("AES");
					c.init(Cipher.DECRYPT_MODE, key);

					//array de bytes do username decifrado
					deciphAux = c.doFinal(ciphuserName);
					username = new String(deciphAux);

					String pwAux;
					int salt;

					//como EXISTE USER faz autenticacao
					if((pwAux = skell.isUser(username)) != null){
						salt = skell.getSalt(username);
						outStream.writeObject(salt);
						ciphAux = (byte []) inStream.readObject();
						deciphAux = c.doFinal(ciphAux);
						password = new String(deciphAux);

						int i = 2;
						while(!pwAux.equals(password)){
							if(i == 0){
								outStream.writeObject(PW_ERROR);
								closeThread();
								return;
							}
							i--;
							outStream.writeObject(PW_ERROR);
							ciphAux = (byte []) inStream.readObject();
							deciphAux = c.doFinal(ciphAux);
							password = new String(deciphAux);
						}

					}

					//se nao houver user ele eh criado
					else{
						outStream.writeObject(SALT_ERROR);
						salt = (int) inStream.readObject();
						ciphAux = (byte []) inStream.readObject();
						deciphAux = c.doFinal(ciphAux);
						password = new String(deciphAux);

						if (skell.isGroup(username) == null){
							if (username.startsWith("\\.") || username.contains("-") || username.contains("/") || username.contains("_")){
								outStream.writeObject(CHAR_ERROR);
								closeThread();
								return;
							}
							skell.createUser(username,salt,password);
						}
						else{
							outStream.writeObject(REG_ERROR);
							closeThread();
							return;
						}
					}


					//Cria uma keystore e vai buscar a public key do user
					FileInputStream kfile = new FileInputStream("myClient.keyStore");
					try {
						KeyStore kstore = KeyStore.getInstance("JKS");
						kstore.load(kfile,ksPwd.toCharArray());
						Certificate cert = kstore.getCertificate(username);
						PublicKey publicKUser = cert.getPublicKey();
					} catch (KeyStoreException | CertificateException e) {
						e.printStackTrace();
					}

					///////////////////////////////////////////////////////////////////
					//////////////////ACABOU O REGISTO E AUTENTICACAO//////////////////
					///////////////////////////////////////////////////////////////////
					/////////////////COMECOU A TRANSFERENCIA DE DADOS//////////////////
					///////////////////////////////////////////////////////////////////


					//recebe o bytearray do numero de args
					ciphAux = (byte[]) inStream.readObject();
					deciphAux = c.doFinal(ciphAux);
					numArgs = Integer.parseInt(new String(deciphAux));

					String [] arguments = new String [(numArgs+1)];
					String [] groupUsers = null;
					String [] argsAux = null;
					//recepcao de parametros do client
					for(int i = 0; i < numArgs; i++){
						if (i == 0){
							ciphAux = (byte[]) inStream.readObject();
							deciphAux = c.doFinal(ciphAux);
							arguments[i] = new String(deciphAux);
						}
						//recebe a mensagem do cliente cifrada
						if (arguments[0].equals("-m")){
							if (i == 1){
								ciphAux = (byte[]) inStream.readObject();
								deciphAux = c.doFinal(ciphAux);
								arguments[i] = new String(deciphAux);
								if (skell.isUser(arguments[1]) == null || skell.isGroup(arguments[1]) == null){
									outStream.writeObject(-1);
									closeThread();
									return;
								}
								outStream.writeObject(1);
								//se o contacto for um grupo envia um array com todos os seus elementos
								if(skell.isGroup(arguments[1]) != null){
									groupUsers = skell.usersInGroup(arguments[1]);
									outStream.writeObject(groupUsers);
								}
								// se contacto for user envia o seu username
								else
									outStream.writeObject(new String [] {arguments[1]});

							}
							else if (i == 2){

								argsAux = new String [groupUsers.length];
								for(int j = 0; j < groupUsers.length; j++){
									argsAux[i] = new String ((byte []) inStream.readObject());
								}
								arguments = concatArrays(arguments, argsAux);
							}
							else{
								ciphAux = (byte[]) inStream.readObject();
								deciphAux = c.doFinal(ciphAux);
								arguments[i] = new String(deciphAux);
							}
						}
					}

					//Se a recepcao de parametros nao for fiavel
					if (skell.validate (arguments) != 1){
						outStream.writeObject(ARGS_ERROR);
						closeThread();
						return;
					}

					else{
						confirm = 1;
						outStream.writeObject(1);//correu tudo bem com os argumentos recebidos
						if (arguments[0] != null){
							switch(arguments[0]){
							case "-m":
								if (skell.isUser(arguments[1]) != null){
									skell.doMoperationTo(arguments[1],arguments[2],username);
									skell.doMoperationFrom(arguments[1],arguments[3],username);
								}
								else if (skell.isGroup(arguments[1]) != null){
									if (skell.hasUserInGroup(arguments[1], username))
										skell.doMGroupOperation(arguments[1],arguments[2],username);
									else
										confirm = -7;
								}
								else
									confirm = -1;
								break;
							case "-f":
								int fileSize = (int) inStream.readObject();
								if (fileSize < 0){
									closeThread();
									return;
								}
								if (arguments[2].startsWith("\\.") || arguments[2].contains("-") || arguments[2].contains("/") || arguments[2].contains("_")){
									closeThread();
									return;
								}
								if (skell.isUser(arguments[1]) != null)
									skell.doFoperation(arguments[1],arguments[2],username,fileSize,inStream);
								else if (skell.isGroup(arguments[1]) != null)
									skell.doFoperationGroup(arguments[1],arguments[2],username,fileSize,inStream);
								else
									confirm = -1;
								break;
							case "-r":
								if (numArgs == 1){
									skell.doR0operation(username,outStream);
								}
								else if (skell.isUser(arguments[1]) != null) {
									outStream.writeObject(1);
									if (numArgs == 2)
										confirm = skell.doR1operation(username,arguments[1],outStream,true);
									else
										confirm = skell.doR2operation(username,arguments[1],arguments[2],outStream,true);
								}
								else if (skell.isGroup(arguments[1]) != null) {
									if (skell.hasUserInGroup(arguments[1], username)) {
										outStream.writeObject(1);
										if (numArgs == 2)
											confirm = skell.doR1operation(username,arguments[1],outStream,false);
										else {
											confirm = skell.doR2operation(username,arguments[1],arguments[2],outStream,false);
											if (confirm == -10)
												break;
										}
									}
									else{
										outStream.writeObject(-7);
										closeThread();
										return;
									}
								}
								else{
									outStream.writeObject(-1);
									closeThread();
									return;
								}
								break;
							case "-a":
								if (skell.isUser(arguments[1]) != null){
									if (skell.isUser(arguments[2]) == null){
										if (arguments[2].startsWith("\\.") || arguments[2].contains("-") || arguments[2].contains("/") || arguments[2].contains("_")){
											confirm = CHAR_ERROR;
										}
										else
											confirm = skell.doAoperation(arguments[1],arguments[2],username);
									}
									else
										confirm = REG_ERROR;
								}
								else
									confirm = -1;
								break;
							case "-d":
								confirm = skell.doDoperation(arguments[1],arguments[2],username);
								break;
							}
						}
					}
					outStream.writeObject(confirm);

				}catch (ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e1) {
					e1.printStackTrace();
				}	


				closeThread();

			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		private String[] concatArrays(String[] arguments, String[] argsAux) {
			String [] result = new String [arguments.length+argsAux.length];
			for (int i = 0; i < arguments.length+argsAux.length; i++){
				if (i < arguments.length)
					result[i] = arguments[i];
				else
					result[i] = argsAux[i-arguments.length];
			}
			return result;
		}

		/**
		 * fecha as streams de comunicacao cliente servidor e servidor cliente
		 * fecha a socket de ligacao ao cliente
		 */
		private void closeThread() {
			try {
				outStream.close();
				inStream.close();

				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}
}
