package de.fraunhofer.iem.secucheck.specifications.CWE89;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSignatureConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.MethodSignature;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
 * <p>
 * The software constructs all or part of an SQL command using externally-influenced input
 * from an upstream component, but it does not neutralize or incorrectly neutralizes special
 * elements that could modify the intended SQL command when it is sent to a downstream component.
 */
@FluentTQLSpecificationClass
public class SqlInjection_AlternativeSpec implements FluentTQLUserInterface {

    /**
     * Source
     */
    public MethodSignature sourceMethodSign = new MethodSignatureConfigurator()
            .atClass("de.fraunhofer.iem.secucheck.todolist.controllers.DatabaseController")
            .returns("java.lang.String")
            .named("showTasks")
            .accepts("org.springframework.ui.Model,java.lang.String")
            .configure();
    public Method sourceMethod = new MethodConfigurator(sourceMethodSign)
            .out().param(1)
            .configure();

    /**
     * Source
     */
    public Method sourceMethod2 = new MethodConfigurator(
            "de.fraunhofer.iem.secucheck.todolist.controllers.DatabaseController: " +
                    "java.lang.String showUrgentTasks(" +
                    "org.springframework.ui.Model," +
                    "java.lang.String)")
            .out().param(1)
            .configure();

    /**
     * Sink
     */
    public Method sinkMethod = new MethodConfigurator(
            "de.fraunhofer.iem.secucheck.todolist.controllers.DatabaseController: " +
                    "java.lang.String getSearchQuery(" +
                    "java.lang.String," +
                    "java.lang.String)")
            .in().param(0)
            .configure();

    /**
     * Sink
     */
    public MethodSignature sinkMethod2Sign = new MethodSignatureConfigurator()
            .atClass("java.sql.Statement")
            .returns("java.sql.ResultSet")
            .named("executeQuery")
            .accepts("java.lang.String")
            .configure();
    public Method sinkMethod2 = new MethodConfigurator(sinkMethod2Sign)
            .in().param(0)
            .configure();

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specifications
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE89_SqlInjection_TF1_WithMethodSign")
                .from(sourceMethod)
                .to(sinkMethod)
                .report("CWE-89 detected: 'SQL Injection' from untrusted value 'String pattern'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        TaintFlowQuery myTF2 = new TaintFlowQueryBuilder("CWE89_SqlInjection_TF2_WithMethodSign")
                .from(sourceMethod2)
                .to(sinkMethod)
                .report("CWE-89 detected: 'SQL Injection' from untrusted value 'String shortname'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        TaintFlowQuery myTF3 = new TaintFlowQueryBuilder("CWE89_SqlInjection_TF3_WithMethodSign")
                .from(sourceMethod2)
                .to(sinkMethod2)
                .report("CWE-89 detected: 'SQL Injection' from untrusted value 'String shortname'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);
        myFluentTQLSpecs.add(myTF2);
        myFluentTQLSpecs.add(myTF3);

        return myFluentTQLSpecs;
    }

}
