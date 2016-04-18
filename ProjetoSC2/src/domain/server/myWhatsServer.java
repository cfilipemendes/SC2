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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
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

	public static void main(String[] args) {
		myWhatsServer server = new myWhatsServer();
		server.startServer(Integer.parseInt(args[0]));
	}

	public void startServer (int port){
		ServerSocket ss = null;

		System.setProperty("javax.net.ssl.keyStore", "myServer.keystore");
		System.setProperty("javax.net.ssl.keyStorePassword", "littlestars");

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

					File fAux = new File (new File(".").getAbsolutePath() + "//" + KEYS_DIR + "//" + username + ".key");

					String pwAux;
					int salt;
					
					//como EXISTE USER faz autenticacao
					if((pwAux = skell.isUser(username)) != null){
						salt = skell.getSalt(username);
						
						outStream.writeObject(salt);
						
						password = (String) inStream.readObject();
						
						int i = 2;
						while(!pwAux.equals(password)){
							if(i == 0){
								outStream.writeObject(PW_ERROR);
								closeThread();
								return;
							}
							i--;
							outStream.writeObject(PW_ERROR);
							password = (String) inStream.readObject();
						}
						//se o servidor tiver feito o login do cliente mas nao tiver a chave publica do mesmo
						if (!fAux.exists()){
							outStream.writeObject(56);
							PublicKey clientPubK = (PublicKey) inStream.readObject();
							FileOutputStream fos = new FileOutputStream (new File(".").getAbsolutePath() + "//" + KEYS_DIR + "//" + username + ".key");
							ObjectOutputStream oos = new ObjectOutputStream(fos);
							oos.writeObject(clientPubK);
							oos.close();
						}
						else{
							outStream.writeObject(58);
							byte[] keyEncoded;
							FileInputStream fis = new FileInputStream (new File(".").getAbsolutePath() + "//" + KEYS_DIR + "//" + username + ".key");
						    ObjectInputStream ois = new ObjectInputStream(fis);
						    keyEncoded = ois.readObject().toString().getBytes();
						    outStream.writeObject(keyEncoded);
						}

					}
					
					//se nao houver user ele eh criado
					else{
						outStream.writeObject(SALT_ERROR);
						salt = (int) inStream.readObject();
						password = (String) inStream.readObject();
						
						if (skell.isGroup(username) == null){
							if (username.startsWith("\\.") || username.contains("-") || username.contains("/") || username.contains("_")){
								outStream.writeObject(CHAR_ERROR);
								closeThread();
								return;
							}
							outStream.writeObject(55);//vai criar um utilizador
							skell.createUser(username,salt,password);
							PublicKey clientPubK = (PublicKey) inStream.readObject();
							FileOutputStream fos = new FileOutputStream (new File(".").getAbsolutePath() + "//" + KEYS_DIR + "//" + username + ".key");
							ObjectOutputStream oos = new ObjectOutputStream(fos);
							oos.writeObject(clientPubK);
							oos.close();
						}
						else{
							outStream.writeObject(REG_ERROR);
							closeThread();
							return;
						}
					}

					outStream.writeObject(1);//correu tudo bem com a autenticacao no servidor




					///////////////////////////////////////////////////////////////////
					//////////////////ACABOU O REGISTO E AUTENTICACAO//////////////////
					///////////////////////////////////////////////////////////////////
					/////////////////COMECOU A TRANSFERENCIA DE DADOS//////////////////
					///////////////////////////////////////////////////////////////////




					int x = (int) inStream.readObject();
					//nao existe privatekey no cliente e vai ser enviada uma nova publickey do mesmo
					if (x == 57){
						PublicKey clientPubK = (PublicKey) inStream.readObject();
						FileOutputStream fos = new FileOutputStream (new File(".").getAbsolutePath() + "//" + KEYS_DIR + "//" + username + ".key");
						ObjectOutputStream oos = new ObjectOutputStream(fos);
						oos.writeObject(clientPubK);
						oos.close();
					}

					//recebe o bytearray do numero de args
					ciphAux = (byte[]) inStream.readObject();
					deciphAux = c.doFinal(ciphAux);
					numArgs = Integer.parseInt(new String(deciphAux));

					String [] arguments = new String [numArgs];
					//recepcao de parametros do client
					for(int i = 0; i < numArgs; i++){
						ciphAux = (byte[]) inStream.readObject();
						deciphAux = c.doFinal(ciphAux);
						arguments [i]= new String(deciphAux);
						//recebe a mensagem do cliente cifrada
						if (arguments[0] == "-m" && i == 2){

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
						if (arguments.length != 0){
							switch(arguments[0]){
							case "-m":
								if (skell.isUser(arguments[1]) != null)
									skell.doMoperation(arguments[1],arguments[2],username);
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
