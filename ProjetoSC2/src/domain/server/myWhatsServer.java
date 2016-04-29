package domain.server;

import java.io.File;
import java.io.FileInputStream;


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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

//Servidor do servico myWhatsServer

public class myWhatsServer {

	private final String USERS_PWS_FILE = "usersAndPws";
	private final String GROUPS_DIR = "groups";
	private final String USERS_DIR = "users";
	private final int SALT_ERROR = -64;
	private final int CHAR_ERROR = -65;
	private final int PW_ERROR = -66;
	private final int REG_ERROR = -68;
	private server_skell skell;
	private static String pwdMac;
	private final static String ksPwd = "littlestars"; 
	private static Mac mac;


	public static void main(String[] args) throws InvalidKeyException, NumberFormatException, NoSuchAlgorithmException, IOException {
		myWhatsServer server = new myWhatsServer();
		pwdMac = args[1];
		server.startServer(Integer.parseInt(args[0]));
	}

	public void startServer (int port) throws NoSuchAlgorithmException, InvalidKeyException, IOException{
		ServerSocket ss = null;

		System.setProperty("javax.net.ssl.keyStore", "myServer.keyStore");
		System.setProperty("javax.net.ssl.keyStorePassword", ksPwd);


		try {
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault( );
			ss = ssf.createServerSocket(port);
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		//inicializa o MAC
		byte [] pwdMacByte = pwdMac.getBytes();
		SecretKey keyMac = new SecretKeySpec(pwdMacByte, "HmacSHA256");
		mac = Mac.getInstance("HmacSHA256");
		mac.init(keyMac);

		//inicializa o scanner
		Scanner sc = new Scanner (System.in);

		//cria um skell do servidor
		skell = new server_skell(USERS_PWS_FILE,GROUPS_DIR, USERS_DIR, mac, sc);

		//verifica se existem todos os MACs
		if (!verifyMacs(mac))
			return;

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
				int numArgs, confirm;
				String username,password;
				try {

					username = (String) inStream.readObject();

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
						outStream.writeObject(1);
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
							skell.createUser(username,salt,password,mac);
							outStream.writeObject(1);
						}
						else{
							outStream.writeObject(REG_ERROR);
							closeThread();
							return;
						}
					}


					//Cria uma keystore e vai buscar a public key do user
					FileInputStream kfile = new FileInputStream("trustedServer.keyStore");
					KeyStore kstore = KeyStore.getInstance("JKS");
					kstore.load(kfile,ksPwd.toCharArray());

					///////////////////////////////////////////////////////////////////
					//////////////////ACABOU O REGISTO E AUTENTICACAO//////////////////
					///////////////////////////////////////////////////////////////////
					/////////////////COMECOU A TRANSFERENCIA DE DADOS//////////////////
					///////////////////////////////////////////////////////////////////


					//recebe o bytearray do numero de args
					numArgs = (int) inStream.readObject();

					byte [] mensagemCifrada;
					String [] arguments = new String [numArgs];
					String [] groupUsers = null;
					boolean user = false;
					boolean group = false;
					byte[] readKey;
					byte [] sig;
					//recepcao de parametros do client
					for(int i = 0; i < numArgs; i++){
						if (i == 0){
							arguments[i] = (String) inStream.readObject();
						}
						else if (arguments[0].equals("-m") || arguments[0].equals("-f")){
							if (i == 1){
								arguments[i] = (String) inStream.readObject();
								if ((skell.isGroup(arguments[1]) == null) && (skell.isUser(arguments[1]) == null)){
									outStream.writeObject(-1);
									closeThread();
									return;
								}
								//se o contacto for um grupo envia um array com todos os seus elementos
								else if(skell.isGroup(arguments[1]) != null){
									group = true;
									outStream.writeObject(1);
									groupUsers = skell.usersInGroup(arguments[1]);
									outStream.writeObject(groupUsers);
								}
								// se contacto for user envia o seu username
								else if (skell.isUser(arguments[1]) != null){
									user = true;
									outStream.writeObject(1);
									outStream.writeObject(new String [] {arguments[1],username});
									groupUsers = new String [] {arguments[1],username};
								}
							}
							else if (i == 2 && arguments[0].equals("-m")){
								sig = (byte[]) inStream.readObject();
								mensagemCifrada = (byte[]) inStream.readObject();

								//guarda as mensagens
								if(user) {
									skell.doMoperation(arguments[1],mensagemCifrada,sig,username);
								}
								else if (group){
									skell.doMGroupOperation(arguments[1],mensagemCifrada,sig,username);
								}
								else{
									outStream.writeObject(-1);
									closeThread();
									return;
								}
								outStream.writeObject(1);
								//recebe e guarda as keys 
								for(int j = 0; j < groupUsers.length; j++){
									readKey = (byte []) inStream.readObject();

									skell.saveKey(arguments[1],groupUsers[j],user,readKey,username,true,null);
								}
							}
							else if (i == 2 && arguments[0].equals("-f")){
								arguments[i] = (String) inStream.readObject();
							}
						}
						else{
							arguments[i] = (String) inStream.readObject();
						}
					}

					confirm = 1;
					outStream.writeObject(1);//correu tudo bem com os argumentos recebidos
					if (arguments.length != 0){
						switch(arguments[0]){
						case "-f":
							int val = (int) inStream.readObject();
							if (val == -1){
								closeThread();
								return;
							}

							sig = (byte []) inStream.readObject();

							int fileSize = (int) inStream.readObject();

							if (arguments[2].startsWith("\\.") || arguments[2].contains("-") || arguments[2].contains("/") || arguments[2].contains("_")){
								closeThread();
								return;
							}
							if (user)
								skell.doFoperation(arguments[1],arguments[2],username,fileSize,sig,inStream);
							else if (group)
								skell.doFoperationGroup(arguments[1],arguments[2],username,fileSize,sig,inStream);
							else{
								confirm = -1;
								break;
							}
							//recebe e guarda as keys 
							for(int j = 0; j < groupUsers.length; j++){
								readKey = (byte []) inStream.readObject();
								skell.saveKey(arguments[1],groupUsers[j],user,readKey,username,false,arguments[2]);
							}
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
										confirm = skell.doAoperation(arguments[1],arguments[2],username,mac);
								}
								else
									confirm = REG_ERROR;
							}
							else
								confirm = -1;
							break;
						case "-d":
							confirm = skell.doDoperation(arguments[1],arguments[2],username,mac);
							break;
						}
					}

					outStream.writeObject(confirm);

				}catch (ClassNotFoundException | NoSuchAlgorithmException | KeyStoreException | CertificateException e1) {
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

	/**
	 * verifica se os MACs do servidor estao correctos, senao termina a execucao do servidor
	 * @param mac MAC para cifrar os ficheiros de modo a podermos comparar
	 * @return true se os MACs estiverem correctos
	 * @throws IOException
	 */
	private boolean verifyMacs(Mac mac) throws IOException {
		byte [] macArray, macArrayAux, usersArray;
		FileInputStream fis;
		File userPwdMac = new File (USERS_PWS_FILE + "MAC");
		File userPwd = new File (USERS_PWS_FILE + ".txt");

		if (userPwdMac.exists()){
			//le o mac array do ficheiro
			macArray = new byte [(int)userPwdMac.length()];
			fis = new FileInputStream (userPwdMac);
			fis.read(macArray);
			fis.close();
			//cria um mac array do ficheiro users e pwds
			usersArray = new byte [(int)userPwd.length()];
			fis = new FileInputStream (userPwd);
			fis.read(usersArray);
			fis.close();
			mac.update(usersArray);
			macArrayAux = mac.doFinal();
			if (Arrays.equals(macArray, macArrayAux))
				System.out.println("MAC do ficheiro das passwords correcto!");
			else{
				System.err.println("Mac do ficheiro das passwords incorrecto!");
				return false;
			}
		}


		File groupDir = new File (GROUPS_DIR);
		String groupname;
		for (File f : groupDir.listFiles()){
			groupname = (f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf(File.separator)+1));
			File groupMac = new File (new File(".").getAbsolutePath() + "//" + GROUPS_DIR + "//" + groupname + "//" + groupname + "MAC");
			File group = new File (new File(".").getAbsolutePath() + "//" + GROUPS_DIR + "//" + groupname + "//" + groupname + ".txt");
			fis = new FileInputStream (group);
			//le o ficheiro 'groupname'
			usersArray = new byte [(int)group.length()];
			fis.read(usersArray);
			fis.close();

			//le o mac array do ficheiro
			macArray = new byte [(int)groupMac.length()];
			fis = new FileInputStream (groupMac);
			fis.read(macArray);
			fis.close();
			//cria um mac array do ficheiro 'groupname'
			mac.update(usersArray);
			macArrayAux = mac.doFinal();
			if (Arrays.equals(macArray,macArrayAux))
				System.out.println("MAC do grupo " + groupname + " esta correcto!");
			else{
				System.err.println("Mac do grupo " + groupname + " esta incorrecto!");
				return false;
			}
		}
		return true;
	}

}
