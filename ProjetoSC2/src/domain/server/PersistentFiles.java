package domain.server;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Scanner;
import javax.crypto.Mac;

public class PersistentFiles {


	private static final int PACKET_SIZE = 1024;
	private BufferedReader br;
	private File users;
	private String usersFile;
	private String groupsDir;
	private String usersDir;
	private Date data;
	private SimpleDateFormat sdf;

	/**
	 * construtor de PersistentFiles
	 * cria os ficheiros MAC
	 * @param usersFile nome do ficheiro de texto dos users e das suas pws
	 * @param groupsDir nome da directoria dos grupos
	 * @param usersDir nome da directoria dos clientes
	 * @param mac MAC para ser criado ou substituido o ficheiro que mantem a integridade das passwords e dos grupos
	 * @param sc Scanner
	 * @throws IOException 
	 */
	public PersistentFiles(String usersFile, String groupsDir, String usersDir, Mac mac, Scanner sc) throws IOException {
		this.usersFile = usersFile;
		users = new File(usersFile + ".txt");
		File userPwdMac = new File (usersFile + "MAC");
		File aux;
		FileInputStream fis;
		FileOutputStream fos;
		byte [] usersArray, macArray;
		sdf = new SimpleDateFormat("dd-MM-yyyy_HH-mm-ss");
		this.groupsDir = groupsDir;
		this.usersDir = usersDir;

		//se nao existir ficheiro de users e pwds
		if(!users.exists()){
			users.createNewFile();
		}
		//se existir ficheiro de users e pwds
		else{
			usersArray = new byte [(int)users.length()];
			fis = new FileInputStream (users);
			fis.read(usersArray);
			fis.close();
			//se nao existir mac do ficheiro de users e pwds 
			if (!userPwdMac.exists()){
				fos = new FileOutputStream (userPwdMac);
				while(true){
					System.out.println("Nao existe MAC a proteger o ficheiro das passwords, gerar MAC? (y/n)");
					String ans = sc.nextLine();
					if (ans.equals("y")){
						mac.update(usersArray);
						macArray = mac.doFinal();
						fos.write(macArray);
						fos.close();
						sc.close();
						break;
					}
					else if (ans.equals("n")){
						System.err.println("O servidor vai ser encerrado!");
						sc.close();
						break;
					}
					else
						System.out.println("Responda apenas com os caracteres 'y' ou 'n'.");
				}
			}
		}
		File dir = new File(usersDir);
		if (!dir.exists())
			dir.mkdir();
		dir = new File(groupsDir);

		//se nao existir directoria de grupos
		if (!dir.exists()){
			dir.mkdir();
		}
		//se existir directoria de grupos
		else {
			String groupname;
			for (File f : dir.listFiles()){
				groupname = (f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf(File.separator)+1));
				File groupMac = new File (new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + groupname + "MAC");
				aux = new File (new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + groupname + ".txt");
				fis = new FileInputStream (aux);
				usersArray = new byte [(int)aux.length()];
				fis.read(usersArray);
				fis.close();
				//se nao existir mac no grupo
				if (!groupMac.exists()){
					fos = new FileOutputStream (groupMac);
					while(true){
						System.out.println("Nao existe MAC a proteger o grupo" + groupname + ", gerar MAC? (y/n)");
						String ans = sc.nextLine();
						if (ans.equals("y")){
							mac.update(usersArray);
							macArray = mac.doFinal();
							fos.write(macArray);
							fos.close();
							sc.close();
							break;
						}
						else if (ans.equals("n")){
							System.err.println("O servidor vai ser encerrado!");
							sc.close();
							break;
						}
						else
							System.out.println("Responda apenas com os caracteres 'y' ou 'n'.");
					}
				}
			}
		}
	}

	/**
	 * verifica se o user corresponde ah sua pw
	 * @param pwd password a ser testatda
	 * @param username nome do utilizador
	 * @return boolean true se a password for correcta
	 * @throws IOException
	 */
	public boolean checkUserPwd(String pwd, String username) throws IOException {
		br = new BufferedReader(new FileReader(users));
		String line;
		while((line = br.readLine()) != null){
			if(line.split(":")[0].equals(username) && line.split(":")[1].equals(pwd)){
				br.close();
				return true;
			}
		}
		br.close();
		return false;
	}

	/**
	 * verifica se existe o user criado
	 * @param username nome do user a verificar
	 * @return String a password do username ou null em caso do username nao existir
	 * @throws IOException
	 */
	public String hasUser(String username) throws IOException {
		br = new BufferedReader(new FileReader(users));
		String line, result;
		int i;
		int size;
		String [] sp;
		while((line = br.readLine()) != null){
			size = line.split(":").length;
			sp = line.split(":");
			if(sp[0].equals(username)){
				result = sp[2];
				i=3;
				while (i < size){
					result = result.concat(":"+sp[i]);
					i++;
				}
				line = br.readLine();
				while ((line != null) && (!line.matches("^(\\w*|\\d*):\\d{6}:.*"))){
					result = result.concat("\n"+line);
					line = br.readLine();
				}
				br.close();
				return result;
			}
		}
		br.close();
		return null;
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
	public synchronized void addUser(String username, int salt, String password, Mac mac) {
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(users,true));
			bw.append(username + ":" + salt + ":" + password);
			bw.newLine();
			bw.flush();
			bw.close();
			File dir = new File (new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + username);
			if (!dir.exists())
				dir.mkdir();

			byte [] macArray;
			byte [] usersArray = new byte [(int)users.length()];
			FileInputStream fis = new FileInputStream (users);
			fis.read(usersArray);
			fis.close();
			mac.update(usersArray);
			macArray = mac.doFinal();
			FileOutputStream fos = new FileOutputStream (new File (usersFile + "MAC"));
			fos.write(macArray);
			fos.close();


		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * cria uma nova mensagem e sig e adiciona ah directoria do remetente e do que enviou
	 * @param to nome do remetente
	 * @param menssagemCifrada conteudo da mensagem cifrada
	 * @param sig byte array com o hash da mensagem
	 * @param from nome de quem enviou
	 */
	public synchronized void newMessage(String to, byte[] menssagemCifrada, byte[] sig, String from) {
		File dir = new File (new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + from + File.separator + to);
		FileOutputStream fos;
		if (!dir.exists())
			dir.mkdir();
		try {
			data = GregorianCalendar.getInstance().getTime();
			fos = new FileOutputStream (new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + from + File.separator + to + File.separator + from + "_" + to + "_" + sdf.format(data) + ".txt");
			fos.write(menssagemCifrada);
			fos.flush();
			fos.close();

			fos = new FileOutputStream(new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + from + File.separator + to + File.separator + from + "_" + to + "_" + sdf.format(data) + ".sig");
			fos.write(sig);
			fos.flush();
			fos.close();

			dir = new File (new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + to + File.separator + from);
			if (!dir.exists())
				dir.mkdir();
			fos = new FileOutputStream(new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + to + File.separator + from + File.separator + from + "_" + to + "_" + sdf.format(data) + ".txt");
			fos.write(menssagemCifrada);
			fos.flush();
			fos.close();

			fos = new FileOutputStream(new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + to + File.separator + from + File.separator + from + "_" + to + "_" + sdf.format(data) + ".sig");
			fos.write(sig);
			fos.flush();
			fos.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * envia uma mensagem e o respectivo sig para um grupo criando la o ficheiro de texto com a conversa
	 * @param groupname nome do grupo para o qual vai ser enviada a mensagem
	 * @param mensagemCifrada conteudo da mensagem cifrada
	 * @param sig array com o hash da mensagem
	 * @param from nome de quem enviou a mensagem
	 */
	public synchronized void newGroupMessage(String groupname, byte[] mensagemCifrada, byte[] sig, String from) {
		try {
			data = GregorianCalendar.getInstance().getTime();
			FileOutputStream fos = new FileOutputStream(new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + from + "_" + groupname + "_" + sdf.format(data) + ".txt");
			fos.write(mensagemCifrada);
			fos.flush();
			fos.close();

			fos = new FileOutputStream(new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + from + "_" + groupname + "_" + sdf.format(data) + ".sig");
			fos.write(sig);
			fos.flush();
			fos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * criacao de um grupo novo
	 * @param groupname nome do grupo
	 * @param creator nome do creador do grupo
	 */
	public synchronized void createGroup (String groupname, String creator){
		File dir = new File (new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname);
		if (!dir.exists())
			dir.mkdir();
		File group = new File (new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + groupname + ".txt");


		try {
			if (!group.exists()){
				group.createNewFile();
				BufferedWriter bw = new BufferedWriter(new FileWriter(group));	
				bw.write(creator);
				bw.newLine();
				bw.flush();
				bw.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * adiciona um utilizador ao grupo
	 * @param groupname nome do grupo ao qual o utilizador vai ser adicionado
	 * @param user nome do utilizador que vai ser adicionado
	 * @param mac MAC para ser criado ou substituido o ficheiro que mantem a integridade das passwords
	 * @throws IOException 
	 */
	public synchronized void addUserToGroup (String groupname, String user, Mac mac) throws IOException{
		File group = new File(new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + groupname + ".txt");
		BufferedWriter bw;

		bw = new BufferedWriter(new FileWriter(group,true));
		bw.append(user);
		bw.newLine();
		bw.flush();
		bw.close();

		byte [] macArray;
		byte [] groupArray = new byte [(int)group.length()];
		FileInputStream fis = new FileInputStream (group);
		fis.read(groupArray);
		fis.close();
		mac.update(groupArray);
		macArray = mac.doFinal();
		FileOutputStream fos = new FileOutputStream (new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + groupname + "MAC");
		fos.write(macArray);
		fos.flush();
		fos.close();
	}

	/**
	 * verifica qual eh o creador do grupo
	 * @param groupname nome do grupo
	 * @return o nome do criador do grupo ou null se nao existir criador
	 */
	public String creatorOfGroup (String groupname){
		File group = new File(new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + groupname + ".txt");
		String creator = null;
		try {
			br = new BufferedReader(new FileReader(group));
			creator = br.readLine();
			br.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return creator;
	}

	/**
	 * remove um utilizador do grupo, se o utilizador a ser removido do grupo for o criador
	 * entao remove tambem o grupo
	 * @param groupname nome do grupo ao qual o utilizador vai ser removido
	 * @param user nome do utilizador que vai ser removido
	 * @param mac MAC para ser criado ou substituido o ficheiro que mantem a integridade do grupo
	 */
	public synchronized void rmFromGroup(String groupname, String user, Mac mac){
		File group = new File(new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + groupname + ".txt");
		if (creatorOfGroup (groupname).equals(user)){
			File groupDir = new File(new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname);
			cleanDir(groupDir);
			groupDir.delete();
		}
		else{
			File groupDir = new File(new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname);
			File temp = new File(new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + "temp.txt");
			BufferedWriter bw;
			String line;
			try {
				br = new BufferedReader(new FileReader(group));
				bw = new BufferedWriter(new FileWriter(temp,true));
				while((line = br.readLine()) != null){
					if(!line.equals(user)){
						bw.append(line);
						bw.newLine();
						bw.flush();
					}
				}
				
				bw.flush();
				bw.close();
				br.close();
				if(group.delete())
					temp.renameTo(group);

				File[] filesDoGrupo = groupDir.listFiles();
				for(int i = 0; i<filesDoGrupo.length; i++)
					if(filesDoGrupo[i].getName().contains(".key." + user))
						filesDoGrupo[i].delete();
				
				byte [] macArray;
				byte [] groupArray = new byte [(int)group.length()];
				FileInputStream fis = new FileInputStream (group);
				fis.read(groupArray);
				fis.close();
				mac.update(groupArray);
				macArray = mac.doFinal();
				FileOutputStream fos = new FileOutputStream (new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + groupname + "MAC");
				fos.write(macArray);
				fos.close();

			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * metodo para apagar todos os ficheiros de uma directoria
	 * @param dir nome da directoria
	 */
	public synchronized void cleanDir (File dir) {
		for(File f : dir.listFiles()){
			f.delete();
		}
	}

	/**
	 * verifica se existe um especifico utilizador no grupo
	 * @param groupname nome do grupo do qual se quer verificar se existe utilizador
	 * @param user nome do utilizador que se quer confirmar se pertence ao grupo
	 * @return boolean true se o utilizador pertencer ao grupo
	 */
	public boolean hasUserInGroup(String groupname, String user){
		File group = new File(new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + groupname + ".txt");
		String line = null;
		try {
			br = new BufferedReader(new FileReader(group));
			while((line = br.readLine()) != null){
				if(line.equals(user)){
					br.close();
					return true;
				}
			}
			br.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return false;
	}

	/**
	 * Verifica quais os utilizadores de um determinado grupo
	 * @param groupname nome doo grupo
	 * @return array de String com o nome de cada utilizador em cada posicao
	 */
	public String[] usersInGroup(String groupname){
		String [] us = null;
		File group = new File(new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + groupname + File.separator + groupname + ".txt");
		int i = 0;
		try {
			br = new BufferedReader(new FileReader(group));
			Object[] aux = br.lines().toArray();
			us = new String [aux.length];
			while (i < aux.length){
				us [i] = aux[i].toString();
				i++;
			}
			br.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return us;
	}

	/**
	 * verifica se existe um grupo no servidor
	 * @param groupname nome do grupo que se pertende verificar se existe
	 * @return nome do criador do grupo ou null se nao existir grupo
	 * @throws IOException
	 */
	public String hasGroup (String groupname) throws IOException{
		File group = new File (new File(".").getAbsolutePath()+ File.separator + groupsDir + File.separator + groupname + File.separator + groupname + ".txt");
		String readLine = null;
		if(group.exists()){
			br = new BufferedReader(new FileReader(group));
			readLine = br.readLine();
			br.close();
			return readLine;
		}
		return null;

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
	public synchronized void saveFile(String contact, String fich, String username, int fileSize, byte[] sig, ObjectInputStream inStream) {
		try {
			File dir = new File (new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + contact + File.separator + username);
			if (!dir.exists())
				dir.mkdir();

			dir = new File (new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + username + File.separator + contact);
			if (!dir.exists())
				dir.mkdir();			

			data = GregorianCalendar.getInstance().getTime();
			byte [] byteArray = new byte [fileSize];
			//Escreve o sig no From
			FileOutputStream fosFrom = new FileOutputStream(new File(".").getAbsolutePath() + 
					File.separator + usersDir + File.separator+ username + File.separator + contact + File.separator + username + "_" + contact + "_" + sdf.format(data) + "_" + fich + ".sig");
			fosFrom.write(sig);
			fosFrom.flush();
			fosFrom.close();
			//Cria o ficheiro no From
			fosFrom = new FileOutputStream(new File(".").getAbsolutePath() + 
					File.separator + usersDir + File.separator+ username + File.separator + contact + File.separator + username + "_" + contact + "_" + sdf.format(data) + "_" + fich);


			//Escreve o sig no To
			FileOutputStream fosTo = new FileOutputStream(new File(".").getAbsolutePath() + 
					File.separator + usersDir + File.separator + contact + File.separator + username + File.separator + username + "_" + contact + "_" + sdf.format(data) + "_" + fich + ".sig");
			fosTo.write(sig);
			fosTo.flush();
			fosTo.close();
			//cria o ficheiro no To
			fosTo = new FileOutputStream(new File(".").getAbsolutePath() + 
					File.separator + usersDir + File.separator + contact + File.separator + username + File.separator + username + "_" + contact + "_" + sdf.format(data) + "_" + fich);

			int current = 0;
			int bytesRead;
			int nCiclo = fileSize/PACKET_SIZE;
			int resto = fileSize%PACKET_SIZE;

			for (int i = 0; i < nCiclo; i++){
				bytesRead = inStream.read(byteArray, current,PACKET_SIZE);
				fosFrom.write(byteArray,current,bytesRead);
				fosFrom.flush();
				fosTo.write(byteArray,current,bytesRead);
				fosTo.flush();
				if (bytesRead > 0)
					current += bytesRead;
			}

			if (resto > 0){
				bytesRead = inStream.read(byteArray, current,resto);
				fosFrom.write(byteArray,current,bytesRead);
				fosFrom.flush();
				fosTo.write(byteArray,current,bytesRead);
				fosTo.flush();
			}
			fosFrom.close();
			fosTo.close();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

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
	public synchronized void saveFileGroup(String contact, String fich, String username, int fileSize, byte[] sig, ObjectInputStream inStream) {
		try {
			data = GregorianCalendar.getInstance().getTime();
			byte [] byteArray = new byte [fileSize];
			FileOutputStream fos = new FileOutputStream(new File(".").getAbsolutePath() + 
					File.separator + groupsDir + File.separator+ contact + File.separator + username + "_" + contact + "_" + sdf.format(data) + "_" + fich + ".sig");
			fos.write(sig);
			fos.flush();
			fos.close();
			fos = new FileOutputStream(new File(".").getAbsolutePath() + 
					File.separator + groupsDir + File.separator+ contact + File.separator + username + "_" + contact + "_" + sdf.format(data) + "_" + fich);

			int current = 0;
			int bytesRead;
			int nCiclo = fileSize/PACKET_SIZE;
			int resto = fileSize%PACKET_SIZE;

			for (int i = 0; i < nCiclo; i++){
				bytesRead = inStream.read(byteArray, current,PACKET_SIZE);
				fos.write(byteArray,current,bytesRead);
				fos.flush();
				if (bytesRead > 0)
					current += bytesRead;
			}

			if (resto > 0){
				bytesRead = inStream.read(byteArray, current,resto);
				fos.write(byteArray,current,bytesRead);
				fos.flush();
			}
			fos.close();
			fos.close();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * verifica se o utilizador tem um ficheiro especifico
	 * @param from nome de quem enviou o ficheiro
	 * @param contact nome do remetente
	 * @param fich nome do ficheiro enviado
	 * @return File se existir o ficheiro fich ou null se nao existir
	 */
	public File userHasFile (String from,String contact, String fich) {
		File myDir = new File (new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + contact + File.separator + from);
		for (File f : myDir.listFiles())
			if (f.toString().contains(fich))
				return f;
		return null;
	}

	/**
	 * existe um ficheiro especifico no grupo
	 * @param group nome do grupo
	 * @param fich nome do ficheiro
	 * @return File ficheiro se existir no grupo ou null se nao existir
	 */
	public File groupHasFile (String group, String fich) {
		File myDir = new File (new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + group);
		String nameAux;
		for (File f : myDir.listFiles()){
			nameAux = (f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf(File.separator)+1));
			if (!nameAux.startsWith(".") && (nameAux.split("_").length == 5))
				if (nameAux.split("_")[4].equals(fich))
					return f;
		}
		return null;
	}

	/**
	 * envia o ficheiro para o cliente
	 * @param from nome de quem enviou o pedido
	 * @param contact nome do remetente
	 * @param fich nome do fichero
	 * @param outStream stream pela qual vai acontecer a comunicacao servidor cliente
	 * @param user se for user vai buscar ao folder de users senao vai ao folder de groups
	 * @return int 1 se for bem sucedido e -10 se nao existir ficheiro
	 */
	public int getFile(String from,String contact, String fich, ObjectOutputStream outStream,boolean user) {
		File myFile,myDir;
		FileInputStream fin;
		int i;
		String keyname,name,signame;
		if (user){
			myFile = userHasFile(from,contact,fich);
			myDir = new File (new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + from + File.separator + contact);
		}
		else{
			myFile = groupHasFile(contact,fich);
			myDir = new File (new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + contact);
		}
		File[] aux = sortFiles(myDir);
		try {
			if (myFile == null){
				outStream.writeObject(-10);
				return -10;			
			}
			name = (myFile.getAbsolutePath().substring(myFile.getAbsolutePath().lastIndexOf(File.separator)+1));
			//envia o tamanho do ficheiro
			int fileSize = (int) myFile.length();
			outStream.writeObject(fileSize);
			byte [] byteArray = new byte [fileSize];
			FileInputStream fis = new FileInputStream (myFile);
			BufferedInputStream bis = new BufferedInputStream (fis);
			int bytesRead;
			int current = 0; 

			int nCiclo = fileSize/PACKET_SIZE;
			int resto = fileSize%PACKET_SIZE;

			for (int j = 0; j < nCiclo; j++){
				bytesRead = bis.read(byteArray,current,PACKET_SIZE);
				outStream.write(byteArray,current,bytesRead);

				outStream.flush();

				if (bytesRead > 0)
					current += bytesRead;
			}
			if (resto > 0){
				bytesRead = bis.read(byteArray,current,resto);
				outStream.write(byteArray,current,bytesRead);
				outStream.flush();
			}

			bis.close();
			fis.close();

			//vai buscar a key
			i = aux.length-1;
			keyname = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
			while(!keyname.contains(name + ".key." + from)){
				i--;
				if (i<0)
					break;
				keyname = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
			}
			int sizerino = (int) aux[i].length();
			byte [] keyCiph = new byte [sizerino];
			fin = new FileInputStream(aux[i]);
			fin.read(keyCiph);
			fin.close();
			outStream.writeObject(sizerino);
			DataOutputStream dos = new DataOutputStream(outStream);
			//envia a key
			dos.write(keyCiph, 0, sizerino);

			//vai buscar o sig
			i = aux.length-1;
			signame = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
			while(!signame.contains(name + ".sig")){
				i--;
				if (i<0)
					break;
				signame = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
			}
			byte [] sig = new byte [(int) aux[i].length()];
			fin = new FileInputStream(aux[i]);
			fin.read(sig);
			fin.close();
			//envia o sig
			outStream.writeObject(sig);


		} catch (IOException e) {
			e.printStackTrace();
		}
		return 1;

	}

	/**
	 * envia para o cliente a conversa completa entre o user e o cliente
	 * @param username nome do utilizador
	 * @param contact nome do contacto entre o qual existiu a conversa
	 * @param outStream stream pela qual vai acontecer a comunicacao cliente servidor
	 * @param user se for user vai buscar a convera a directoria dos users senao vai buscar a directoria dos grupos
	 * @return 1 se for tudo bem sucedido
	 */
	public int getContactConv(String username, String contact, ObjectOutputStream outStream, boolean user) {
		try {
			File myDir;
			if (user)
				myDir = new File (new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + username + File.separator + contact);
			else
				myDir = new File (new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + contact);
			int nFiles = myDir.list().length;
			outStream.writeObject(nFiles);
			String [] fileName;
			String name,keyname,signame;
			String [] finalF;
			File[] aux = sortFiles(myDir);
			int i;
			boolean checkKey;

			for (File f : aux){
				name = (f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf(File.separator)+1));
				if (!name.startsWith(".") && !name.contains(".sig") && !name.contains(".key")){

					//vai buscar a key
					i = aux.length-1;
					checkKey = true;
					keyname = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
					while(!keyname.contains(name + ".key." + username)){
						i--;
						if (i<0){
							checkKey = false;
							break;
						}
						keyname = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
					}
					if (checkKey){

						finalF = new String [5];
						fileName = name.split("_");
						//se o ficheiro for message
						if (fileName.length == 4){
							finalF [0] = fileName[0];
							finalF [1] = fileName[1];
							finalF [2] = (fileName[2] + "_" + fileName[3]);
							finalF [4] = "-m";
							//vai buscar mensagem
							FileInputStream fin = new FileInputStream(f);
							byte [] fileContent = new byte[(int)f.length()];
							fin.read(fileContent);
							fin.close();

							outStream.writeObject(finalF);
							outStream.flush();
							outStream.writeObject(fileContent);
							outStream.flush();

							//le a key
							int sizerino = (int) aux[i].length();
							byte [] keyCiph = new byte [sizerino];
							fin = new FileInputStream(aux[i]);
							fin.read(keyCiph);
							fin.close();
							outStream.writeObject(sizerino);
							DataOutputStream dos = new DataOutputStream(outStream);
							//envia a key
							dos.write(keyCiph, 0, sizerino);

							//vai buscar o sig
							i = aux.length-1;
							String nameAux = name.split("\\.")[0];
							signame = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
							while(!signame.contains(nameAux + ".sig")){
								i--;
								if (i<0)
									break;
								signame = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
							}
							byte [] sig = new byte [(int) aux[i].length()];
							fin = new FileInputStream(aux[i]);
							fin.read(sig);
							fin.close();
							//envia o sig
							outStream.writeObject(sig);

						}
						//se o ficheiro for file
						else if (fileName.length == 5){
							finalF [0] = fileName[0];
							finalF [1] = fileName[1];
							finalF [2] = (fileName[2] + "_" + fileName[3]);
							finalF [3] = fileName[4];
							finalF [4] = "-f";
							outStream.writeObject(finalF);
							outStream.flush();
						}
						else{
							outStream.writeObject(null);
							outStream.flush();
						}
					}
					//se nao existir key para o username
					else{
						outStream.writeObject(null);
						outStream.flush();
					}
				}
				//se nao existir ficheiro
				else{
					outStream.writeObject(null);
					outStream.flush();
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return 1;
	}

	/**
	 * le o conteudo de um ficheiro
	 * @param f nome do ficheiro
	 * @return String com o conteudo do ficheiro
	 */
	public String readFile (File f) {
		StringBuilder sb = new StringBuilder ();
		try {
			BufferedReader br = new BufferedReader (new FileReader (f));
			String line;

			while ((line = br.readLine()) != null) {
				sb.append(line);
				sb.append("\n");
			}

			br.close();
		}catch (IOException e) {
			e.printStackTrace();
		}
		return sb.toString();
	}

	/**
	 * envia para o cliente as ultimas mensagens que o user tem com os seu contactos e com os seus grupos
	 * @param username nome do utilizador
	 * @param outStream stream pela qual vai acontecer a comunicacao cliente servidor
	 */
	public void getLatestConvs(String username, ObjectOutputStream outStream) {
		File myDir = new File (new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + username + File.separator);
		String name, keyname, signame;
		String [] finalF,fileName;
		File[] aux;
		int i;
		try {
			//envia o numero de contactos
			i = numFiles(myDir);
			outStream.writeObject(i);
			outStream.flush();

			for (File f : myDir.listFiles()){
				//em caso de files gerados pelo sistema
				if (!f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf(File.separator)+1).startsWith(".")) {

					aux = sortFiles(f);
					i = aux.length-1;
					if (aux.length == 0){
						outStream.writeObject(null);
						outStream.flush();
					}
					else{
						name = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
						while(name.startsWith(".") || name.contains(".sig") || name.contains(".key")){
							i--;
							if (i<0)
								break;
							name = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
						}
						if (!name.startsWith(".")){
							finalF = new String [5];
							fileName = name.split("_");
							//se o ficheiro for message
							if (fileName.length == 4){
								finalF [0] = fileName[0];
								finalF [1] = fileName[1];
								finalF [2] = (fileName[2] + "_" + fileName[3]);
								finalF [4] = "-m";
								//vai buscar mensagem
								FileInputStream fin = new FileInputStream(aux[i]);
								byte [] fileContent = new byte[(int)aux[i].length()];
								fin.read(fileContent);
								fin.close();

								//envia a mensagem cifrada
								outStream.writeObject(finalF);
								outStream.flush();
								outStream.writeObject(fileContent);
								outStream.flush();

								//vai buscar a key
								i = aux.length-1;
								keyname = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
								while(!keyname.contains(name + ".key." + username)){
									i--;
									if (i<0)
										break;
									keyname = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
								}
								int sizerino = (int) aux[i].length();
								byte [] keyCiph = new byte [sizerino];
								fin = new FileInputStream(aux[i]);
								fin.read(keyCiph);
								fin.close();
								outStream.writeObject(sizerino);
								DataOutputStream dos = new DataOutputStream(outStream);
								//envia a key
								dos.write(keyCiph, 0, sizerino);

								//vai buscar o sig
								i = aux.length-1;
								String nameAux = name.split("\\.")[0];
								signame = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
								while(!signame.contains(nameAux + ".sig")){
									i--;
									if (i<0)
										break;
									signame = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
								}
								byte [] sig = new byte [(int) aux[i].length()];
								fin = new FileInputStream(aux[i]);
								fin.read(sig);
								fin.close();
								//envia o sig
								outStream.writeObject(sig);

							}
							//se o ficheiro for file
							else if (fileName.length == 5 && (!fileName[4].contains(".key") || !fileName[4].contains(".sig"))){
								finalF [0] = fileName[0];
								finalF [1] = fileName[1];
								finalF [2] = (fileName[2] + "_" + fileName[3]);
								finalF [3] = fileName[4];
								finalF [4] = "-f";
								outStream.writeObject(finalF);
								outStream.flush();
							}
							else{
								outStream.writeObject(null);
								outStream.flush();
							}
						}
						else{
							outStream.writeObject(null);
							outStream.flush();
						}
					}
				}
			}



			myDir = new File (new File(".").getAbsolutePath() + File.separator + groupsDir);
			i = myDir.listFiles().length;
			outStream.writeObject(i);
			outStream.flush();
			for (File f : myDir.listFiles()){
				//em caso de files gerados pelo sistema
				if (!f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf(File.separator)+1).startsWith(".")) {
					aux = sortFiles(f);
					i = aux.length-1;
					if (aux.length == 0){
						outStream.writeObject(null);
						outStream.flush();
					}
					else if (!hasUserInGroup(f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf(File.separator)+1), username)){
						outStream.writeObject(null);
						outStream.flush();
					}
					else{
						name = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
						while(name.startsWith(".") || name.equals(f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf(File.separator)+1) + ".txt")
								|| name.contains(".sig") || name.contains(".key")){
							i--;
							if (i<0)
								break;
							name = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
						}
						if (!name.startsWith(".")){
							finalF = new String [5];
							fileName = name.split("_");
							//se o ficheiro for message
							if (fileName.length == 4){
								finalF [0] = fileName[0];
								finalF [1] = fileName[1];
								finalF [2] = (fileName[2] + "_" + fileName[3]);
								finalF [4] = "-m";
								//vai buscar mensagem
								FileInputStream fin = new FileInputStream(aux[i]);
								byte [] fileContent = new byte[(int)aux[i].length()];
								fin.read(fileContent);
								fin.close();

								//envia a mensagem cifrada
								outStream.writeObject(finalF);
								outStream.flush();
								outStream.writeObject(fileContent);
								outStream.flush();


								//vai buscar a key
								i = aux.length-1;
								keyname = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
								while(!keyname.contains(name + ".key." + username)){
									i--;
									if (i<0)
										break;
									keyname = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
								}
								int sizerino = (int) aux[i].length();
								byte [] keyCiph = new byte [sizerino];
								fin = new FileInputStream(aux[i]);
								fin.read(keyCiph);
								fin.close();
								outStream.writeObject(sizerino);
								DataOutputStream dos = new DataOutputStream(outStream);
								//envia a key
								dos.write(keyCiph, 0, sizerino);

								//vai buscar o sig
								i = aux.length-1;
								String nameAux = name.split("\\.")[0];
								signame = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
								while(!signame.contains(nameAux + ".sig")){
									i--;
									if (i<0)
										break;
									signame = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf(File.separator)+1));
								}
								byte [] sig = new byte [(int) aux[i].length()];
								fin = new FileInputStream(aux[i]);
								fin.read(sig);
								fin.close();
								//envia o sig
								outStream.writeObject(sig);

							}
							//se o ficheiro for file
							else if (fileName.length == 5){
								finalF [0] = fileName[0];
								finalF [1] = fileName[1];
								finalF [2] = (fileName[2] + "_" + fileName[3]);
								finalF [3] = fileName[4];
								finalF [4] = "-f";
								outStream.writeObject(finalF);
								outStream.flush();
							}
							else{
								outStream.writeObject(null);
								outStream.flush();
							}
						}
					}
				}
			}
		}catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * calcula o numero de ficheiros de uma directoria
	 * @param myDir nome da directoria
	 * @return numero de ficheiros pertencentes ah directoria
	 */
	private int numFiles(File myDir) {
		int i = 0;
		for (File f : myDir.listFiles()){
			if (!f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf(File.separator)+1).startsWith("."))
				i++;
		}
		return i;

	}

	/**
	 * organiza os ficheiros de uma directoria por ordem de criacao
	 * @param myDir nome da directoria a ser organizada
	 * @return
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public File [] sortFiles (File myDir){
		File[] aux = myDir.listFiles();
		Arrays.sort(aux, new Comparator()		
		{
			public int compare(final Object o1, final Object o2){
				return new Long(((File)o1).lastModified()).compareTo(new Long(((File) o2).lastModified()));
			}
		});
		return aux;
	}

	/**
	 * vai buscar o numero salt de um cliente especifica
	 * @param username nome do cliente
	 * @return numero salt
	 * @throws IOException
	 */
	public int getSalt(String username) throws IOException {
		br = new BufferedReader(new FileReader(users));
		String line;
		while((line = br.readLine()) != null){
			if(line.split(":")[0].equals(username)){
				br.close();
				return Integer.parseInt(line.split(":")[1]);
			}
		}
		br.close();
		return 0;
	}

	/**
	 * guarda a key num determinado cliente
	 * @param to nome do cliente para quem foi enviado o ficheiro cifrado com a key
	 * @param contact contacto do user que consegue fazer unwrap da key
	 * @param readKey array de bytes com o conteudo da key cifrada
	 * @param username nome do utilizador que enviou o ficheiro
	 * @param msg true se for uma mensagem ou false se for um ficheiro
	 * @param filename nome do ficheiro ou null se for uma mensagem
	 */
	public void saveContactKey(String to, String contact, byte [] readKey, String username, boolean msg, String filename) {
		File dir;
		File message;
		File messageTo;
		try {
			if (username.equals(contact)){
				dir = new File (new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + username + File.separator + to); 
				if (!dir.exists())
					dir.mkdir();
				if (msg)
					message = new File(new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + username + File.separator + to + File.separator + username + "_" + to + "_" + sdf.format(data) + ".txt.key." + contact);
				else
					message = new File(new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + username + File.separator + to + File.separator + username + "_" + to + "_" + sdf.format(data) + "_" + filename + ".key." + contact);

				message.createNewFile();
				FileOutputStream fos = new FileOutputStream(message);
				fos.write(readKey);
				fos.flush();
				fos.close();

			}

			else{
				dir = new File (new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + to + File.separator + username);
				if (!dir.exists())
					dir.mkdir();
				if (msg)
					messageTo = new File(new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + to + File.separator + username + File.separator + username + "_" + to + "_" + sdf.format(data) + ".txt.key." + contact);
				else
					messageTo = new File(new File(".").getAbsolutePath() + File.separator + usersDir + File.separator + to + File.separator + username + File.separator + username + "_" + to + "_" + sdf.format(data) + "_" + filename + ".key." + contact);

				messageTo.createNewFile();
				FileOutputStream fos = new FileOutputStream(messageTo);
				fos.write(readKey);
				fos.flush();
				fos.close();

			}
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	/**
	 * guarda as keys num grupo
	 * @param to nome do grupo
	 * @param contact nome do utilizador que consegue fazer unwrap da key
	 * @param readKey array de byte com o conteudo da key
	 * @param from nome do utilizador que enviou o ficheiro ou a mensagem
	 * @param msg true se for uma mensagem ou false se for um ficheiro
	 * @param filename nome do ficheiro ou null se for uma mensagem
	 */
	public void saveGroupKey(String to, String contact, byte[] readKey, String from, boolean msg, String filename) {
		File message;
		try {
			if (msg)
				message = new File (new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + to + File.separator + from + "_" + to + "_" + sdf.format(data) + ".txt.key." + contact);
			else
				message = new File (new File(".").getAbsolutePath() + File.separator + groupsDir + File.separator + to + File.separator + from + "_" + to + "_" + sdf.format(data) + "_" + filename + ".key." + contact);

			message.createNewFile();
			FileOutputStream fos = new FileOutputStream(message);
			fos.write(readKey);
			fos.flush();
			fos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

}




