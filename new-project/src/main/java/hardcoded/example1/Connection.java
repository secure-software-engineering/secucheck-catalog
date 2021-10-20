package hardcoded.example1;

import java.sql.DriverManager;
import java.sql.SQLException;

public class Connection {

	public static void main(String[] args) throws SQLException {
		String url = args[0];
		String uname = args[1];
		performConnection(url, uname);
	}
 
	public static void performConnection(String url, String username) throws SQLException {	
		// SOURCE
		// the same password is used for all usernames
        String password = "tiger";
        
        // SINK
        DriverManager.getConnection(url, username, password);
    }

}
