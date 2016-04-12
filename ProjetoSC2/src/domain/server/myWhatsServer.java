package domain.server;

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

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

import domain.server.myWhatsServer.ServerThread;

//Servidor do servico myWhatsServer

public class myWhatsServer {

	private final String USERS_PWS_FILE = "usersAndPws";
	private final String GROUPS_DIR = "groups";
	private final String USERS_DIR = "users";
	private final int CHAR_ERROR = -65;
	private final int PW_ERROR = -66;
	private final int ARGS_ERROR = -67;
	private final int REG_ERROR = -68;
	private server_skell skell;

	public static void main(String[] args) {
		myWhatsServer server = new myWhatsServer();
		server.startServer(Integer.parseInt(args[0]));
	}

	@SuppressWarnings("resource")
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
		skell = new server_skell(USERS_PWS_FILE,GROUPS_DIR, USERS_DIR);

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
				String username,password;
				try {


					username = (String) inStream.readObject();
					password = (String) inStream.readObject();
					String pwAux;
					//Primeiro verifica que se nao houver user ele eh criado
					if((pwAux = skell.isUser(username)) == null){
						if (skell.isGroup(username) == null){
							if (username.startsWith("\\.") || username.contains("-") || username.contains("/") || username.contains("_")){
								outStream.writeObject(CHAR_ERROR);
								closeThread();
								return;
							}
							skell.createUser(username,password);
						}
						else{
							outStream.writeObject(REG_ERROR);
							closeThread();
							return;
						}
					}
					else{ // senao, como EXISTE USER faz autenticacao
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
					}
					outStream.writeObject(1);//correu tudo bem com a autenticacao

					numArgs = (int) inStream.readObject();


					String [] arguments = new String [numArgs];
					//recepcao de parametros do client
					for(int i = 0; i < numArgs; i++){
						arguments [i]= (String) inStream.readObject();
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

				}catch (ClassNotFoundException e1) {
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
