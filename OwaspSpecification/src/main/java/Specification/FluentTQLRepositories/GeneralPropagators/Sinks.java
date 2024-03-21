package Specification.FluentTQLRepositories.GeneralPropagators;

import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.FluentTQLRepositoryClass;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.MethodPackage.Method;

@FluentTQLRepositoryClass
public class Sinks {
    public static Method sink_00008 = new MethodConfigurator(
            "java.sql.PreparedStatement: " +
                    "java.sql.ResultSet executeQuery()")
            .in().thisObject()
            .configure();

    public static Method sink_00018 = new MethodConfigurator(
            "java.sql.Statement: " +
                    "int executeUpdate(java.lang.String)")
            .in().param(0)
            .configure();

    public static Method sink_00024 = new MethodConfigurator(
            "java.sql.PreparedStatement: " +
                    "boolean execute()")
            .in().thisObject()
            .configure();

    public static Method sink_00025 = new MethodConfigurator(
            "org.springframework.jdbc.core.JdbcTemplate: " +
                    "java.lang.Object queryForObject(java.lang.String,java.lang.Class)")
            .in().param(0)
            .configure();

    public static Method sink_00026 = new MethodConfigurator(
            "org.springframework.jdbc.core.JdbcTemplate: " +
                    "org.springframework.jdbc.support.rowset.SqlRowSet queryForRowSet(java.lang.String)")
            .in().param(0)
            .configure();

    public static Method sink_00027 = new MethodConfigurator(
            "java.sql.Statement: " +
                    "int executeUpdate(java.lang.String)")
            .in().param(0)
            .configure();

    public static Method sink_00341 = new MethodConfigurator(
            "org.springframework.jdbc.core.JdbcTemplate: " +
                    "int[] batchUpdate(java.lang.String[])")
            .in().param(0)
            .configure();
}
