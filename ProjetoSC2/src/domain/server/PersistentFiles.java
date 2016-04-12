package domain.server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileFilter;
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

public class PersistentFiles {


	private static final int PACKET_SIZE = 1024;
	private BufferedReader br;
	private File users;
	private String groupsDir;
	private String usersDir;
	private Date data;
	private SimpleDateFormat sdf;

	/**
	 * construtor de PresistentFiles
	 * @param usersFile nome do ficheiro de texto dos users e das suas pws
	 * @param groupsDir nome da directoria dos grupos
	 * @param usersDir nome da directoria dos clientes
	 */
	public PersistentFiles(String usersFile, String groupsDir, String usersDir) {
		users = new File(usersFile + ".txt");
		sdf = new SimpleDateFormat("dd-MM-yyyy_HH-mm-ss");
		this.groupsDir = groupsDir;
		this.usersDir = usersDir;
		if(!users.exists())
			try {
				users.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
		File dir = new File(usersDir);
		if (!dir.exists())
			dir.mkdir();
		dir = new File(groupsDir);
		if (!dir.exists())
			dir.mkdir();
	}

	/**
	 * verifica se o user corresponde a sua pw
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
	 * @return boolean true se o user existir
	 * @throws IOException
	 */
	public String hasUser(String username) throws IOException {
		br = new BufferedReader(new FileReader(users));
		String line;
		while((line = br.readLine()) != null){
			if(line.split(":")[0].equals(username)){
				br.close();
				return line.split(":")[1];
			}
		}
		br.close();
		return null;
	}

	/**
	 * adiciona um user ao servidor
	 * adiciona o seu username e a sua password ao ficheiro
	 * adiciona uma directoria com o seu nome na directoria dos users
	 * @param username nome do utilizador
	 * @param password password do utilizador
	 */
	public synchronized void addUser(String username, String password) {
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(users,true));
			bw.append(username + ":" + password);
			bw.newLine();
			bw.flush();
			bw.close();
			File dir = new File (new File(".").getAbsolutePath() + "//" + usersDir + "//" + username);
			if (!dir.exists())
				dir.mkdir();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * cria uma nova mensagem e adiciona ah directoria do remetente e do que enviou
	 * @param to nome do remetente
	 * @param mess conteudo da mensagem
	 * @param from nome de quem enviou
	 */
	public synchronized void newMessage(String to, String mess, String from) {
		File dir = new File (new File(".").getAbsolutePath() + "//" + usersDir + "//" + from + "//" + to);
		if (!dir.exists())
			dir.mkdir();
		try {
			data = GregorianCalendar.getInstance().getTime();
			File message = new File (new File(".").getAbsolutePath() + "//" + usersDir + "//" + from + "//" + to + "//" + from + "_" + to + "_" + sdf.format(data) + ".txt");
			message.createNewFile();
			BufferedWriter bw = new BufferedWriter(new FileWriter(message));	
			bw.write(mess);
			bw.flush();
			bw.close();

			dir = new File (new File(".").getAbsolutePath() + "//" + usersDir + "//" + to + "//" + from);
			if (!dir.exists())
				dir.mkdir();
			File messageTo = new File (new File(".").getAbsolutePath() + "//" + usersDir + "//" + to + "//" + from + "//" + from + "_" + to + "_" + sdf.format(data) + ".txt");
			messageTo.createNewFile();
			bw = new BufferedWriter(new FileWriter(messageTo));	
			bw.write(mess);
			bw.flush();
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * envia uma mensagem para um grupo criando la o ficheiro de texto com a conversa
	 * @param groupname nome do grupo para o qual vai ser enviada a mensagem
	 * @param mess conteudo da mensagem
	 * @param from nome de quem enviou a mensagem
	 */
	public synchronized void newGroupMessage(String groupname, String mess, String from) {
		try {
			data = GregorianCalendar.getInstance().getTime();
			File message = new File (new File(".").getAbsolutePath() + "//" + groupsDir + "//" + groupname + "//" + from + "_" + groupname + "_" + sdf.format(data) + ".txt");
			message.createNewFile();
			BufferedWriter bw = new BufferedWriter(new FileWriter(message));	
			bw.write(mess);
			bw.flush();
			bw.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
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
		File dir = new File (new File(".").getAbsolutePath() + "//" + groupsDir + "//" + groupname);
		if (!dir.exists())
			dir.mkdir();
		File group = new File (new File(".").getAbsolutePath() + "//" + groupsDir + "//" + groupname + "//" + groupname + ".txt");


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
	 */
	public synchronized void addUserToGroup (String groupname, String user){
		File group = new File(new File(".").getAbsolutePath() + "//" + groupsDir + "//" + groupname + "//" + groupname + ".txt");
		BufferedWriter bw;
		try {
			bw = new BufferedWriter(new FileWriter(group,true));
			bw.append(user);
			bw.newLine();
			bw.flush();
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * verifica qual eh o creador do grupo
	 * @param groupname nome do grupo
	 * @return o nome do creador do grupo ou null se nao existir creador
	 */
	public String creatorOfGroup (String groupname){
		File group = new File(new File(".").getAbsolutePath() + "//" + groupsDir + "//" + groupname + "//" + groupname + ".txt");
		String creator = null;
		try {
			br = new BufferedReader(new FileReader(group));
			creator = br.readLine();
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
	 */
	public synchronized void rmFromGroup(String groupname, String user){
		File group = new File(new File(".").getAbsolutePath() + "//" + groupsDir + "//" + groupname + "//" + groupname + ".txt");
		if (creatorOfGroup (groupname).equals(user)){
			File groupDir = new File(new File(".").getAbsolutePath() + "//" + groupsDir + "//" + groupname);
			cleanDir(groupDir);
			groupDir.delete();
		}
		else{
			File temp = new File(new File(".").getAbsolutePath() + "//" + groupsDir + "//" + groupname + "//temp.txt");
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
				bw.close();
				br.close();
				if(group.delete())
					temp.renameTo(group);

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
		File group = new File(new File(".").getAbsolutePath() + "//" + groupsDir + "//" + groupname + "//" + groupname + ".txt");
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
	 * verifica se existe um grupo no servidor
	 * @param groupname nome do grupo que se pertende verificar se existe
	 * @return nome do criador do grupo ou null se nao existir grupo
	 * @throws IOException
	 */
	public String hasGroup (String groupname) throws IOException{
		File group = new File (new File(".").getAbsolutePath()+ "//" + groupsDir + "//" + groupname + "//" + groupname + ".txt");
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
	 * recebe um ficheiro do cliente e guarda na pasta do remetente e de quem o enviou
	 * @param contact nome do remetente
	 * @param fich nome do ficheiro
	 * @param username nome de quem envia o ficheiro
	 * @param fileSize tamanho do ficheiro em bytes
	 * @param inStream stream pela qual vai acontecer a comunicacao cliente servidor
	 */
	public synchronized void saveFile(String contact, String fich, String username, int fileSize, ObjectInputStream inStream) {
		try {
			File dir = new File (new File(".").getAbsolutePath() + "//" + usersDir + "//" + contact + "//" + username);
			if (!dir.exists())
				dir.mkdir();
			
			dir = new File (new File(".").getAbsolutePath() + "//" + usersDir + "//" + username + "//" + contact);
			if (!dir.exists())
				dir.mkdir();
			
			data = GregorianCalendar.getInstance().getTime();
			byte [] byteArray = new byte [fileSize];
			FileOutputStream fosFrom = new FileOutputStream(new File(".").getAbsolutePath() + 
					"//" + usersDir + "//"+ username + "//" + contact + "//" + username + "_" + contact + "_" + sdf.format(data) + "_" + fich);
			BufferedOutputStream bosFrom = new BufferedOutputStream(fosFrom);
			FileOutputStream fosTo = new FileOutputStream(new File(".").getAbsolutePath() + 
					"//" + usersDir + "//" + contact + "//" + username + "//" + username + "_" + contact + "_" + sdf.format(data) + "_" + fich);
			BufferedOutputStream bosTo = new BufferedOutputStream(fosTo);

			int current = 0;
			int bytesRead;
			int nCiclo = fileSize/PACKET_SIZE;
			int resto = fileSize%PACKET_SIZE;

			for (int i = 0; i < nCiclo; i++){
				bytesRead = inStream.read(byteArray, current,PACKET_SIZE);
				bosFrom.write(byteArray,current,bytesRead);
				bosFrom.flush();
				bosTo.write(byteArray,current,bytesRead);
				bosTo.flush();
				if (bytesRead > 0)
					current += bytesRead;
			}

			if (resto > 0){
				bytesRead = inStream.read(byteArray, current,resto);
				bosFrom.write(byteArray,current,bytesRead);
				bosFrom.flush();
				bosTo.write(byteArray,current,bytesRead);
				bosTo.flush();
			}
			bosFrom.close();
			bosTo.close();
			fosFrom.close();
			fosTo.close();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	/**
	 * guarda um ficheiro no grupo
	 * @param contact nome do remetente
	 * @param fich nome do ficheiro
	 * @param username nome de quem enviou o ficheiro
	 * @param fileSize tamanho do ficheiro em bytes
	 * @param inStream stream pela qual vai acontecer a comunicacao cliente servidor
	 */
	public synchronized void saveFileGroup(String contact, String fich, String username, int fileSize, ObjectInputStream inStream) {
		try {
			data = GregorianCalendar.getInstance().getTime();
			byte [] byteArray = new byte [fileSize];
			FileOutputStream fos = new FileOutputStream(new File(".").getAbsolutePath() + 
					"//" + groupsDir + "//"+ contact + "//" + username + "_" + contact + "_" + sdf.format(data) + "_" + fich);
			BufferedOutputStream bos = new BufferedOutputStream(fos);

			int current = 0;
			int bytesRead;
			int nCiclo = fileSize/PACKET_SIZE;
			int resto = fileSize%PACKET_SIZE;

			for (int i = 0; i < nCiclo; i++){
				bytesRead = inStream.read(byteArray, current,PACKET_SIZE);
				bos.write(byteArray,current,bytesRead);
				bos.flush();
				if (bytesRead > 0)
					current += bytesRead;
			}

			if (resto > 0){
				bytesRead = inStream.read(byteArray, current,resto);
				bos.write(byteArray,current,bytesRead);
				bos.flush();
			}
			bos.close();
			bos.close();

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
		File myDir = new File (new File(".").getAbsolutePath() + "//" + usersDir + "//" + contact + "//" + from);
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
		File myDir = new File (new File(".").getAbsolutePath() + "//" + groupsDir + "//" + group);
		String nameAux;
		for (File f : myDir.listFiles()){
			nameAux = (f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf("/")+1));
			if (!nameAux.startsWith(".") && (nameAux.split("_").length == 5))
				if (nameAux.split("_")[4].equals(fich))
					return f;
		}
		return null;
	}

	/**
	 * envia o ficheiro para o cliente
	 * @param from nome de quem enviou o ficheiro
	 * @param contact nome do remetente
	 * @param fich nome do fichero
	 * @param outStream stream pela qual vai acontecer a comunicacao servidor cliente
	 * @param user se for user vai buscar ao folder de users senao vai ao folder de groups
	 * @return int 1 se for bem sucedido e -10 se nao existir ficheiro
	 */
	public int getFile(String from,String contact, String fich, ObjectOutputStream outStream,boolean user) {
		File myFile;
		if (user)
			myFile = userHasFile(from,contact,fich);
		else
			myFile = groupHasFile(contact,fich);
		try {
			if (myFile == null){
				outStream.writeObject(-10);
				return -10;			
			}

			int fileSize = (int) myFile.length();
			outStream.writeObject(fileSize);
			byte [] byteArray = new byte [fileSize];
			FileInputStream fis = new FileInputStream (myFile);
			BufferedInputStream bis = new BufferedInputStream (fis);
			int bytesRead;
			int current = 0; 

			int nCiclo = fileSize/PACKET_SIZE;
			int resto = fileSize%PACKET_SIZE;

			for (int i = 0; i < nCiclo; i++){
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
				myDir = new File (new File(".").getAbsolutePath() + "//" + usersDir + "//" + contact + "//" + username);
			else
				myDir = new File (new File(".").getAbsolutePath() + "//" + groupsDir + "//" + contact);
			int nFiles = myDir.list().length;
			outStream.writeObject(nFiles);
			String [] fileName;
			String nameAux;
			String [] finalF;
			File[] aux = sortFiles(myDir);

			for (File f : aux){
				nameAux = (f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf("/")+1));
				if (!nameAux.startsWith(".")){
					finalF = new String [4];
					fileName = nameAux.split("_");
					//se o ficheiro for message
					if (fileName.length == 4){
						finalF [0] = fileName[0];
						finalF [1] = fileName[1];
						finalF [2] = (fileName[2] + "_" + fileName[3]);
						finalF [3] = readFile(f);
						outStream.writeObject(finalF);
						outStream.flush();
					}
					//se o ficheiro for file
					else if (fileName.length == 5){
						finalF [0] = fileName[0];
						finalF [1] = fileName[1];
						finalF [2] = (fileName[2] + "_" + fileName[3]);
						finalF [3] = fileName[4];
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
		File myDir = new File (new File(".").getAbsolutePath() + "//" + usersDir + "//" + username);
		String nameAux;
		String [] finalF,fileName;
		File[] aux;
		int i;
		try {
			i = myDir.listFiles().length;
			outStream.writeObject(i);
			outStream.flush();
			for (File f : myDir.listFiles()){
				aux = sortFiles(f);
				i = 0;
				if (aux.length == 0){
					outStream.writeObject(null);
					outStream.flush();
				}
				else{
					nameAux = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf("/")+1));
					while((nameAux.startsWith(".")) && (aux.length > i+1)){
						i++;
						nameAux = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf("/")+1));
					}
					if (!nameAux.startsWith(".")){
						finalF = new String [4];
						fileName = nameAux.split("_");
						//se o ficheiro for message
						if (fileName.length == 4){
							finalF [0] = fileName[0];
							finalF [1] = fileName[1];
							finalF [2] = (fileName[2] + "_" + fileName[3]);
							finalF [3] = readFile(aux[i]);
							outStream.writeObject(finalF);
							outStream.flush();
						}
						//se o ficheiro for file
						else if (fileName.length == 5){
							finalF [0] = fileName[0];
							finalF [1] = fileName[1];
							finalF [2] = (fileName[2] + "_" + fileName[3]);
							finalF [3] = fileName[4];
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

			myDir = new File (new File(".").getAbsolutePath() + "//" + groupsDir);
			i = myDir.listFiles().length;
			outStream.writeObject(i);
			outStream.flush();
			for (File f : myDir.listFiles()){
				aux = sortFiles(f);
				i = 0;
				if (aux.length == 0){
					outStream.writeObject(null);
					outStream.flush();
				}
				else if (!hasUserInGroup(f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf("/")+1), username)){
					outStream.writeObject(null);
					outStream.flush();
				}
				else{
					nameAux = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf("/")+1));
					while((nameAux.startsWith(".") || nameAux.equals(f.getAbsolutePath().substring(f.getAbsolutePath().lastIndexOf("/")+1) + ".txt"))
							&& (aux.length > i+1)){
						i++;
						nameAux = (aux[i].getAbsolutePath().substring(aux[i].getAbsolutePath().lastIndexOf("/")+1));
					}
					if (!nameAux.startsWith(".")){
						finalF = new String [4];
						fileName = nameAux.split("_");
						//se o ficheiro for message
						if (fileName.length == 4){
							finalF [0] = fileName[0];
							finalF [1] = fileName[1];
							finalF [2] = (fileName[2] + "_" + fileName[3]);
							finalF [3] = readFile(aux[i]);
							outStream.writeObject(finalF);
							outStream.flush();
						}
						//se o ficheiro for file
						else if (fileName.length == 5){
							finalF [0] = fileName[0];
							finalF [1] = fileName[1];
							finalF [2] = (fileName[2] + "_" + fileName[3]);
							finalF [3] = fileName[4];
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
		}catch (IOException e) {
			e.printStackTrace();
		}
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

}




