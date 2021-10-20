package nullpointer.example1;

public class Main {

	public static void main(String[] args) {
		String arg1 = null;
		String arg2 = arg1;
		sink(arg2);
	}

	private static void sink(String param) {
		System.out.println(param);
	}
}
