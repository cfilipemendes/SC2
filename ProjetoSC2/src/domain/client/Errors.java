package domain.client;

public class Errors {
	
	private static final String flags = "-p-m-f-r-a-d";
	private final static int CHAR_ERROR = -65;
	private final static int ARGS_ERROR = -67;
	private final static int REG_ERROR = -68;
	
	/**
	 * Metodo utilizado exclusivamente para definir a lista de erros que o 
	 * nosso programa devolve.
	 * @param x id do erro a retornar
	 * @return String que descreve o erro que ocorreu || confirmacao
	 */
	public static String errorConfirm(int x){
		switch(x){
		case 1: 	
			return "Operacao Realizada com Sucesso!";
		case -1:
			return "O cliente nao existe";
		case -2:
			return "Input insuficiente";
		case -3:
			return "Input incorreto";
		case -4:
			return "Input excede o esperado";
		case -5:
			return "Nao se pode adicionar a si mesmo ao grupo!";
		case -6:
			return "Esse utilizador ja se encontra no grupo!";
		case -7:
			return "Esse utilizador nao pertence ao grupo!";
		case -8:
			return "Nao e o criador do grupo";
		case -9:
			return "Nao existe esse grupo";
		case -10:
			return "Ficheiro nao existe no servidor!";
		case -11:
			return "Ficheiro nao existe no cliente!";
		case -12:
			return "O ficheiro nao pode conter os seguintes caracteres: _,/,-,.";
		case CHAR_ERROR:
			return "O nome nao pode conter os seguintes caracteres: _,/,-,.";
		case ARGS_ERROR:
			return "O servidor recebeu dados CORROMPIDOS!";
		case REG_ERROR:
			return "O nome ja existe";
		default :
			return "Resultado nao conclusivo.";
		}
	}

	/**
	 * -1 x == null
	 * -2 flag -p n e a primeira
	 * -3 argumento da pass e uma flag
	 * -4 argumentos insuficientes para a pass
	 * -5 flag invalida a seguir ao -p
	 * -6 ordem errada da flag
	 * -7 argumentos das flag invalidos
	 * -10 falta password
	 * @param args lista de argumentos recebidos no cliente
	 * @return o tipo de erro em int
	 */
	public static int validate (String [] args){
		StringBuilder y = new StringBuilder ();
		if (args == null)
			return -1;

		int size = args.length-1;

		for (int i = 2; i <= size; i++){
			switch(args[i]){
			case "-p":
				if(y.length() != 0)
					return -2;
				if(i+1 <= size){
					if(flags.contains(args[i+1])){
						return -3;
					}
				}else
					return -4;

				if(i+2 < size)
					if(!flags.contains(args[i+2]))
						return -5;
				y.append('p');
				break;
			case "-m":
				if (y.toString().contains("m") || 
						y.toString().contains("f") ||
						y.toString().contains("r") ||
						y.toString().contains("a") ||
						y.toString().contains("d"))
					return -6;
				if(!argTwo(i, args, size))
					return -7;
				y.append('m');
				break;
			case "-f":
				if (y.toString().contains("m") || 
						y.toString().contains("f") ||
						y.toString().contains("r") ||
						y.toString().contains("a") ||
						y.toString().contains("d"))
					return -6;
				if(!argTwo(i, args, size))
					return -7;
				y.append('f');
				break;
			case "-r":
				if (y.toString().contains("m") || 
						y.toString().contains("f") ||
						y.toString().contains("r") ||
						y.toString().contains("a") ||
						y.toString().contains("d"))
					return -6;
				if (!argTwo(i, args, size) && !argOne(i, args, size) && size != i){
					return -7;
				}
				y.append('r');
				break;
			case "-a":
				if (y.toString().contains("m") || 
						y.toString().contains("f") ||
						y.toString().contains("r") ||
						y.toString().contains("a") ||
						y.toString().contains("d"))
					return -6;
				if(!argTwo(i, args, size))
					return -7;
				y.append('a');
				break;
			case "-d":
				if (y.toString().contains("m") || 
						y.toString().contains("f") ||
						y.toString().contains("r") ||
						y.toString().contains("a") ||
						y.toString().contains("d"))
					return -6;
				if(!argTwo(i, args, size))
					return -7;
				y.append('d');
				break;
			}
		}
		if (!y.toString().contains("p"))
			return -10;
		return 1;
	}	

	/**
	 * Verifica se existem dois argumentos validos depois da flag 
	 * @param i indice do ciclo
	 * @param args os argumentos recebidos pelo cliente desde a flag
	 * @param size numero de parametros que sucedem a flag
	 * @return true se existirem dois argumentos depois da flag
	 */
	//Se tiver dois argumentos ah frente da flag
	private static boolean argTwo(int i , String [] args, int size){
		if(i+2 > size)
			return false;
		if (flags.contains(args[i+1]) || flags.contains(args[i+2]))
			return false;
		return true;
	}
	/**
	 * Verifica se existe um argumento valido depois da flag 
	 * @param i indice do ciclo
	 * @param args os argumentos recebidos pelo cliente desde a flag
	 * @param size numero de parametros que sucedem a flag
	 * @return true se existir um argumento depois da flag
	 */
	//Se tiver um unico argumento ah frente da flag
	private static boolean argOne(int i, String [] args, int size){
		if (i+1 > size)
			return false;
		if (flags.contains(args[i+1]))
			return false;
		return true;
	}
}

