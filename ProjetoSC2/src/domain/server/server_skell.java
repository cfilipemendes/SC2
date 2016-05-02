package domain.server;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Scanner;

import javax.crypto.Mac;

/***************************************************************************
 *  Trabalho realizado por:
 *  Andre Vieira 44868
 *	Cesar Mendes 44864
 *	Gil Correia  44851
 ***************************************************************************/

public class server_skell {

	private static PersistentFiles files;
	private static final String flags = "-p-m-f-r-a-d";

	/**
	 * Construtor da classe server skell
	 * @param usersFile nome do ficheiro de users e pws
	 * @param groupsDir nome da pasta de grupos
	 * @param usersDir nome da pasta de utilizadores
	 * @param mac MAC para ser criado ou substituido o ficheiro que mantem a integridade das passwords e dos grupos
	 * @param sc Scanner
	 * @throws IOException 
	 */
	public server_skell (String usersFile, String groupsDir, String usersDir, Mac mac, Scanner sc) throws IOException{
		files = new PersistentFiles(usersFile,groupsDir,usersDir, mac, sc);
	}

	/**
	 * Verifica o login de um utilizador
	 * @param pwd password login do utilizador
	 * @param username nome login do utilizador
	 * @return true se login for bem sucedido
	 * @throws IOException
	 */
	public boolean authenticate (String pwd, String username) throws IOException{
		return files.checkUserPwd(pwd,username);
	}

	/**
	 * verifica se existe o user criado
	 * @param username nome do user a verificar
	 * @return true se o user existir
	 * @throws IOException
	 */
	public String isUser(String username) throws IOException {
		return files.hasUser(username);
	}

	/**
	 * adiciona um user ao servidor
	 * adiciona o seu username, o salt e a sua password cifrada ao ficheiro
	 * adiciona uma directoria com o seu nome na directoria dos users
	 * @param username nome do utilizador
	 * @param salt numero de 6 digitos gerado aleatoriamente
	 * @param password password do utilizador cifrada
	 * @param mac MAC para ser criado ou substituido o ficheiro que mantem a integridade das passwords
	 */
	public void createUser(String username, int salt, String password, Mac mac) {
		files.addUser(username,salt,password,mac);
	}

	/**
	 * verifica se existe um grupo no servidor
	 * @param groupname nome do grupo que se pertende verificar se existe
	 * @return nome do criador do grupo ou null se nao existir grupo
	 * @throws IOException
	 */
	public String isGroup(String groupname) throws IOException{
		return files.hasGroup(groupname);
	}

	/**
	 * Verifica se um utilizador existe num grupo
	 * @param groupname nome do grupo do qual se quer verificar se existe utilizador
	 * @param user nome do utilizador que se quer confirmar se pertence ao grupo
	 * @return true se o utilizador pertencer ao grupo
	 */
	public boolean hasUserInGroup(String groupname, String user){
		return files.hasUserInGroup(groupname, user);

	}

	/**
	 * Verifica quais os utilizadores de um determinado grupo
	 * @param groupname nome doo grupo
	 * @return array de String com o nome de cada utilizador em cada posicao
	 */
	public String[] usersInGroup(String groupname){
		return files.usersInGroup(groupname);
	}

	/**
	 * Valida os argumentos passados ao programa 
	 * @param arguments string de argumentos enviados do cliente ao servidor
	 * @return -1 x == null
	 * @return -2 flag -p n e a primeira
	 * @return -3 argumento da pass e uma flag
	 * @return -4 argumentos insuficientes para a pass
	 * @return -5 flag invalida a seguir ao -p
	 * @return -6 ordem errada da flag
	 * @return -7 argumentos das flag invalidos
	 * @return -10 falta password
	 */
	public int validate(String[] arguments) {
		StringBuilder confirm = new StringBuilder ();
		if (arguments == null)
			return -1;
		int size = arguments.length-1;
		if (size > 2)
			return -8;
		if (size == 0)
			return 1;

		for (int i = 0; i <= size; i++){
			switch(arguments[i]){
			case "-m":
				if (confirm.toString().contains("m") || 
						confirm.toString().contains("f") ||
						confirm.toString().contains("r") ||
						confirm.toString().contains("a") ||
						confirm.toString().contains("d"))
					return -6;
				if(!argTwo(i, arguments, size))
					return -7;
				confirm.append('m');
				break;
			case "-f":
				if (confirm.toString().contains("m") || 
						confirm.toString().contains("f") ||
						confirm.toString().contains("r") ||
						confirm.toString().contains("a") ||
						confirm.toString().contains("d"))
					return -6;
				if(!argTwo(i, arguments, size))
					return -7;
				confirm.append('f');
				break;
			case "-r":
				if (confirm.toString().contains("m") || 
						confirm.toString().contains("f") ||
						confirm.toString().contains("r") ||
						confirm.toString().contains("a") ||
						confirm.toString().contains("d"))
					return -6;
				if (!argTwo(i, arguments, size) && !argOne(i, arguments, size) && size != i)
					return -7;
				confirm.append('r');
				break;
			case "-a":
				if (confirm.toString().contains("m") || 
						confirm.toString().contains("f") ||
						confirm.toString().contains("r") ||
						confirm.toString().contains("a") ||
						confirm.toString().contains("d"))
					return -6;
				if(!argTwo(i, arguments, size))
					return -7;
				confirm.append('a');
				break;
			case "-d":
				if (confirm.toString().contains("m") || 
						confirm.toString().contains("f") ||
						confirm.toString().contains("r") ||
						confirm.toString().contains("a") ||
						confirm.toString().contains("d"))
					return -6;
				if(!argTwo(i, arguments, size))
					return -7;
				confirm.append('d');
				break;
			}
		}
		return 1;
	}

	/**
	 * Testa se uma flag de 2 parametros e bem passado ao programa
	 * @param i indice do parametro a avaliar
	 * @param args argumentos passados ao programa
	 * @param size tamanho dos parametros
	 * @return true se os argumentos forem validos
	 */
	private static boolean argTwo(int i , String [] args, int size){
		if(i+2 > size)
			return false;
		if (flags.contains(args[i+1]) || flags.contains(args[i+2]))
			return false;
		return true;
	}
	/**
	 * Testa se uma flag so de um argumento e bem passado ao programa
	 * @param i indice do parametro a avaliar
	 * @param args argumentos passados ao programa
	 * @param size tamanho dos parametros
	 * @return true se os argumentos forem validos 
	 */
	//Se tiver um unico argumento ah frente da flag
	private static boolean argOne(int i, String [] args, int size){
		if (i+1 > size)
			return false;
		if (flags.contains(args[i+1]))
			return false;
		return true;
	}
	
	/**
	 * cria uma nova mensagem e sig e adiciona ah directoria do remetente e do que enviou
	 * @param to nome do remetente
	 * @param menssagemCifrada conteudo da mensagem cifrada
	 * @param sig byte array com o hash da mensagem
	 * @param from nome de quem enviou
	 */
	public void doMoperation(String to, byte[] menssagemCifrada, byte[] sig, String from) {
		files.newMessage(to, menssagemCifrada, sig, from);
	}
	
	/**
	 * envia uma mensagem e o respectivo sig para um grupo criando la o ficheiro de texto com a conversa
	 * @param groupname nome do grupo para o qual vai ser enviada a mensagem
	 * @param mensagemCifrada conteudo da mensagem cifrada
	 * @param sig array com o hash da mensagem
	 * @param from nome de quem enviou a mensagem
	 */
	public void doMGroupOperation(String groupname, byte[] mensagemCifrada, byte[] sig, String from) {
		files.newGroupMessage(groupname, mensagemCifrada, sig, from);
	}
	
	/**
	 * recebe um ficheiro do cliente e o respectivo sig e guarda na pasta do remetente e de quem o enviou
	 * @param contact nome do remetente
	 * @param fich nome do ficheiro
	 * @param username nome de quem envia o ficheiro
	 * @param fileSize tamanho do ficheiro em bytes
	 * @param inStream stream pela qual vai acontecer a comunicacao cliente servidor
	 * @param sig array com o hash do ficheiro
	 */
	public void doFoperation(String contact, String fich, String username, int fileSize,byte[] sig, ObjectInputStream inStream) {
		files.saveFile(contact,fich,username,fileSize,sig,inStream);
	}

	/**
	 * guarda um ficheiro e o respectivo sig no grupo
	 * @param contact nome do remetente
	 * @param fich nome do ficheiro
	 * @param username nome de quem enviou o ficheiro
	 * @param fileSize tamanho do ficheiro em bytes
	 * @param sig array com o hash da mensagem
	 * @param inStream stream pela qual vai acontecer a comunicacao cliente servidor
	 */
	public void doFoperationGroup(String contact, String fich, String username, int fileSize,byte[] sig, ObjectInputStream inStream) {	
		files.saveFileGroup(contact,fich,username,fileSize,sig,inStream);
	}

	/**
	 * vai buscar a ultima coisa que foi enviada ou recebida para cada contacto
	 * @param username nome do utilizador autenticado
	 * @param outStream stream de dados do socket 
	 */
	public void doR0operation(String username, ObjectOutputStream outStream) {
		files.getLatestConvs(username,outStream);
	}

	/**
	 * vai buscar tudo o que foi enviado e recebido para um so contacto ou grupo
	 * @param username utilizador que executa a operacao
	 * @param contact contacto ou grupo do qual se quer ver tudo o que foi enviado e recebido
	 * @param outStream stream de dados do socket
	 * @param user boolean para controlar se o contacto escolhido e um utilizador ou um grupo
	 * @return 1 em caso de sucesso
	 */
	public int doR1operation(String username, String contact, ObjectOutputStream outStream,boolean user) {
		if (user)
			return files.getContactConv(username,contact,outStream,user);
		return files.getContactConv(username,contact,outStream,user);
	}

	/**
	 * Pede um ficheiro de um contacto do servidor
	 * @param contact contacto do qual se pretende obter o ficheiro
	 * @param fich nome do ficheiro pretendido
	 * @return 1 caso seja feito com sucesso 
	 * @return -10 caso o ficheiro nao exista
	 */
	public int doR2operation(String from,String contact, String fich,ObjectOutputStream outStream,boolean user) {
		return files.getFile(from,contact,fich,outStream,user);
	}

	/**
	 * adiciona um user a um grupo
	 * @param user contacto a adicionar ao grupo
	 * @param group nome do grupo
	 * @param from utilizador que executa o pedido
	 * @param mac MAC para ser criado ou substituido o ficheiro que mantem a integridade das passwords
	 * @return -5 caso o utilizador a adicionar seja o mesmo que executa o pedido
	 * @return -6 se o contacto ja estiver no grupo
	 * @return -8 se o utilizador nao for o criador do grupo
	 * @throws IOException 
	 */
	public int doAoperation(String user, String group, String from, Mac mac) throws IOException {
		int confirm = 1;
		if (from.equals(user))
			return -5;
		String creator;
		//se existir grupo
		if((creator = files.hasGroup(group)) != null){
			if(creator.equals(from)){
				if (!files.hasUserInGroup(group,user)){
					files.addUserToGroup(group,user,mac);
				}
				else
					confirm = -6;
			}
			else
				confirm = -8;
		}
		//se nao existir grupo
		else{
			files.createGroup(group,from);
			files.addUserToGroup(group,user,mac);
		}
		return confirm;
	}

	/**
	 * remove um utilizador de um grupo
	 * @param user contacto do utilizador
	 * @param group nome do grupo
	 * @param mac MAC para ser criado ou substituido o ficheiro que mantem a integridade das passwords
	 * @return -7 caso o user nao esteja no grupo
	 * @return -8 caso o utilizador nao seja dono do grupo e como tal nao pode remover~
	 * @return -9 se o grupo nao existir
	 * @throws IOException 
	 */
	public int doDoperation(String user, String group, String from, Mac mac) throws IOException {
		String creator;
		int confirm = 1;
		if((creator = files.hasGroup(group)) != null){
			if(creator.equals(from)){
				if(files.hasUserInGroup(group,user)){
					files.rmFromGroup(group,user,mac);
				}
				else
					confirm = -7;
			}
			else
				confirm = -8;
		}
		else
			confirm = -9;
		return confirm;
	}

	/**
	 * vai buscar o numero salt de um cliente especifica
	 * @param username nome do cliente
	 * @return numero salt
	 * @throws IOException
	 */
	public int getSalt(String user) throws IOException {
		return files.getSalt(user);
	}

	/**
	 * guarda as keys nas respectivas directorias
	 * @param to nome do cliente para quem foi enviado o ficheiro cifrado com a key
	 * @param contact contacto do user que consegue fazer unwrap da key
	 * @param user true se for user false se for grupo
	 * @param readKey array de bytes com o conteudo da key cifrada
	 * @param username nome do utilizador que enviou o ficheiro
	 * @param msg true se for uma mensagem ou false se for um ficheiro
	 * @param filename nome do ficheiro ou null se for uma mensagem
	 */
	public void saveKey(String to,String contact, boolean user, byte [] readKey, String username,boolean msg, String filename) {
		if (user)
			files.saveContactKey(to,contact,readKey,username,msg,filename);
		else
			files.saveGroupKey(to,contact,readKey,username,msg,filename);

	}

}