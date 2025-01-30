package de.fraunhofer.iem.secucheck.InternalFluentTQL.catalogSpecifications.FuentTQLRepositories.Sinks;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSelector;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSet;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLRepositoryClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.InFlowParam;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.InFlowThisObject;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;

/**
 * Multiple Sinks definition for Prepared-Statements
 *
 * @author Ranjith Krishnamurthy
 * @author Goran
 */
@FluentTQLRepositoryClass
public class PreparedStatementSinks {
    @InFlowThisObject
    public static final Method sink1 = new MethodSelector(
            "java.sql.PreparedStatement: java.sql.ResultSet executeQuery()",
            "CWE-89"
    );

    @InFlowThisObject
    @InFlowParam(parameterID = {0})
    public static final Method sink2 = new MethodSelector(
            "java.sql.PreparedStatement: java.sql.ResultSet executeQuery(java.lang.String)",
            "CWE-89"
    );

    @InFlowThisObject
    public static final Method sink3 = new MethodSelector(
            "java.sql.PreparedStatement: boolean execute()",
            "CWE-89"
    );

    @InFlowThisObject
    @InFlowParam(parameterID = {0})
    public static final Method sink4 = new MethodSelector(
            "java.sql.PreparedStatement: boolean execute(java.lang.String)",
            "CWE-89"
    );

    /**
     * This MethodSet contains some of the sink methods in Prepared Statements.
     */
    public static MethodSet prepSinks = new MethodSet("PrepSinks")
            .addMethod(sink1)
            .addMethod(sink2)
            .addMethod(sink3)
            .addMethod(sink4);
}
