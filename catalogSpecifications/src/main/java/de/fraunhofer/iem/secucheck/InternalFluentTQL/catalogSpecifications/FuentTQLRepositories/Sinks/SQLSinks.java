package de.fraunhofer.iem.secucheck.InternalFluentTQL.catalogSpecifications.FuentTQLRepositories.Sinks;

import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodSelector;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodSet;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.FluentTQLRepositoryClass;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.InFlowParam;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.MethodPackage.Method;

/**
 * Multiple Sinks definition for SQL.
 *
 * @author Ranjith Krishnamurthy
 * @author Goran
 */
@FluentTQLRepositoryClass
public class SQLSinks {
    //Below are the few sink methods from SQL.
    @InFlowParam(parameterID = {0})
    public static final Method sink1 = new MethodSelector("java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)");

    @InFlowParam(parameterID = {0})
    public static final Method sink2 = new MethodSelector("java.sql.Statement: int executeUpdate(java.lang.String)");

    @InFlowParam(parameterID = {0})
    public static final Method sink3 = new MethodSelector("java.sql.Statement: int executeQuery(java.lang.String, int)");

    @InFlowParam(parameterID = {0})
    public static final Method sink4 = new MethodSelector("java.sql.Statement: long executeLargeUpdate(java.lang.String)");

    @InFlowParam(parameterID = {0})
    public static final Method sink5 = new MethodSelector("java.sql.Statement: boolean execute(java.lang.String)");

    /**
     * This MethodSet contains some of the sink methods in SQL statements.
     */
    public static MethodSet sqlSinks = new MethodSet("sqlSinks")
            .addMethod(sink1)
            .addMethod(sink2)
            .addMethod(sink3)
            .addMethod(sink4)
            .addMethod(sink5);
}
