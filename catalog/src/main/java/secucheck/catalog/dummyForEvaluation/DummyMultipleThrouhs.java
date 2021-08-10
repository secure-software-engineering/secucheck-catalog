package secucheck.catalog.dummyForEvaluation;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import java.sql.*;
import java.util.Scanner;

public class DummyMultipleThrouhs {
    public static ResultSet getEmployeeInformationWithoutSanitizer() throws EncodingException {
        Scanner mySC = new Scanner(System.in);

        // Method nextLine is a source that takes input from user.
        String employeeID = mySC.nextLine();

        employeeID = ESAPI.encoder().decodeForHTML(employeeID);
        mySC.close();

        employeeID = ESAPI.encoder().decodeFromURL(employeeID);

        try {
            Connection myConnection = DriverManager.getConnection("jdbc:hsqldb:mem:EMPLOYEES", "test", "test");
            Statement myStatement = myConnection.createStatement();

            employeeID = ESAPI.encoder().encodeForLDAP(employeeID);
            employeeID = ESAPI.encoder().encodeForHTMLAttribute(employeeID);
            employeeID = ESAPI.encoder().encodeForJavaScript(employeeID);
            employeeID = ESAPI.encoder().encodeForURL(employeeID);
            employeeID = ESAPI.encoder().encodeForVBScript(employeeID);
            employeeID = ESAPI.encoder().encodeForXML(employeeID);
            employeeID = ESAPI.encoder().encodeForXMLAttribute(employeeID);
            employeeID = ESAPI.encoder().encodeForXPath(employeeID);

            // Method executeQuery is a sink that perform sensitive operation and leaks the
            // data.
            ResultSet queryResult = myStatement.executeQuery("SELECT * FROM EMPLOYEE where EID = " + employeeID);
            return queryResult;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static ResultSet getEmployeeInformationWithSanitizer() throws SQLException, EncodingException {
        Scanner mySC = new Scanner(System.in);

        // Method nextLine is a source that takes input from user.
        String userInput = mySC.nextLine();

        userInput = ESAPI.encoder().decodeForHTML(userInput);
        mySC.close();

        userInput = ESAPI.encoder().decodeFromURL(userInput);



        Connection myConnection = DriverManager.getConnection("jdbc:hsqldb:mem:EMPLOYEES", "test", "test");
        Statement myStatement = myConnection.createStatement();

        userInput = ESAPI.encoder().encodeForLDAP(userInput);
        userInput = ESAPI.encoder().encodeForHTMLAttribute(userInput);
        userInput = ESAPI.encoder().encodeForJavaScript(userInput);
        userInput = ESAPI.encoder().encodeForURL(userInput);
        userInput = ESAPI.encoder().encodeForVBScript(userInput);
        userInput = ESAPI.encoder().encodeForXML(userInput);
        userInput = ESAPI.encoder().encodeForXMLAttribute(userInput);
        userInput = ESAPI.encoder().encodeForXPath(userInput);

        PolicyFactory POLICY_DEFINITION = new HtmlPolicyBuilder().toFactory();

        // Method sanitize is a sanitizer that sanitizes the user input.
        String employeeID = POLICY_DEFINITION.sanitize(userInput);

        // Method executeQuery is a sink that perform sensitive operation and leaks the
        // data.
        ResultSet queryResult = myStatement.executeQuery("SELECT * FROM EMPLOYEE where EID = " + employeeID);

        return queryResult;

    }
}
