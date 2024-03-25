package Specification.FluentTQLRepositories.GeneralPropagators;

import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.FluentTQLRepositoryClass;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.MethodPackage.Method;

@FluentTQLRepositoryClass
public class Sinks {
    public static Method sink_8 = new MethodConfigurator(
            "java.sql.PreparedStatement: " +
                    "java.sql.ResultSet executeQuery()")
            .in().thisObject()
            .configure();

    public static Method sink_18_27 = new MethodConfigurator(
            "java.sql.Statement: " +
                    "int executeUpdate(java.lang.String)")
            .in().param(0)
            .configure();

    public static Method sink_24_37 = new MethodConfigurator(
            "java.sql.PreparedStatement: " +
                    "boolean execute()")
            .in().thisObject()
            .configure();

    public static Method sink_25 = new MethodConfigurator(
            "org.springframework.jdbc.core.JdbcTemplate: " +
                    "java.lang.Object queryForObject(java.lang.String,java.lang.Class)")
            .in().param(0)
            .configure();

    public static Method sink_26 = new MethodConfigurator(
            "org.springframework.jdbc.core.JdbcTemplate: " +
                    "org.springframework.jdbc.support.rowset.SqlRowSet queryForRowSet(java.lang.String)")
            .in().param(0)
            .configure();

    public static Method sink_341 = new MethodConfigurator(
            "org.springframework.jdbc.core.JdbcTemplate: " +
                    "int[] batchUpdate(java.lang.String[])")
            .in().param(0)
            .configure();

    public static Method sink_32_33 = new MethodConfigurator(
            "org.springframework.jdbc.core.JdbcTemplate: " +
                    "void execute(java.lang.String)")
            .in().param(0)
            .configure();

    public static Method sink_34 = new MethodConfigurator(
            "java.sql.Statement: " +
                    "boolean execute(java.lang.String,int)")
            .in().param(0)
            .configure();

    public static Method sink_38 = new MethodConfigurator(
            "org.springframework.jdbc.core.JdbcTemplate: " +
                    "java.util.List query(java.lang.String,org.springframework.jdbc.core.RowMapper)")
            .in().param(0)
            .configure();
}
