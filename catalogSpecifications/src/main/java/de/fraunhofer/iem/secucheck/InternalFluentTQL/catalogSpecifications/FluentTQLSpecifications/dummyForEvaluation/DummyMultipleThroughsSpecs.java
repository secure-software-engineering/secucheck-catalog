package de.fraunhofer.iem.secucheck.InternalFluentTQL.catalogSpecifications.FluentTQLSpecifications.dummyForEvaluation;

import de.fraunhofer.iem.secucheck.fluenttql.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodSelector;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.*;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.SpecificationInterface.FluentTQLUserInterface;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodConfigurator;

import java.util.ArrayList;
import java.util.List;

@FluentTQLSpecificationClass
public class DummyMultipleThroughsSpecs implements FluentTQLUserInterface {
    @OutFlowReturnValue
    public Method source = new MethodSelector("java.util.Scanner: java.lang.String nextLine()");

    @InFlowParam(parameterID = {0})
    public Method sink = new MethodSelector("java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)");

    public Method rp1 = new MethodConfigurator("org.owasp.esapi.Encoder: java.lang.String decodeForHTML(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method rp2 = new MethodConfigurator("org.owasp.esapi.Encoder: java.lang.String decodeFromURL(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method rp3 = new MethodConfigurator("org.owasp.esapi.Encoder: java.lang.String encodeForLDAP(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method rp4 = new MethodConfigurator("org.owasp.esapi.Encoder: java.lang.String encodeForHTMLAttribute(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method rp5 = new MethodConfigurator("org.owasp.esapi.Encoder: java.lang.String encodeForJavaScript(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method rp6 = new MethodConfigurator("org.owasp.esapi.Encoder: java.lang.String encodeForURL(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method rp7 = new MethodConfigurator("org.owasp.esapi.Encoder: java.lang.String encodeForVBScript(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method rp8 = new MethodConfigurator("org.owasp.esapi.Encoder: java.lang.String encodeForXML(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method rp9 = new MethodConfigurator("org.owasp.esapi.Encoder: java.lang.String encodeForXMLAttribute(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method rp10 = new MethodConfigurator("org.owasp.esapi.Encoder: java.lang.String encodeForXPath(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("DummyMTSpec")
                .from(source)
                .through(rp1)
                .through(rp2)
                .through(rp3)
                .through(rp4)
                .through(rp5)
                .through(rp6)
                .through(rp7)
                .through(rp8)
                .through(rp9)
                .through(rp10)
                .to(sink)
                .report("There is a Dummy SQL Injection - CWE89!!!")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }
}