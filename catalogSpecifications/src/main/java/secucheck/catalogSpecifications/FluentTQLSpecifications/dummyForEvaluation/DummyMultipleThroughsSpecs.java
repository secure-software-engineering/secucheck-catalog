package secucheck.catalogSpecifications.FluentTQLSpecifications.dummyForEvaluation;

import secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import secucheck.InternalFluentTQL.dsl.MethodSelector;
import secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import secucheck.InternalFluentTQL.dsl.annotations.AnalysisEntryPoint;
import secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import secucheck.InternalFluentTQL.dsl.annotations.InFlowParam;
import secucheck.InternalFluentTQL.dsl.annotations.OutFlowReturnValue;
import secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

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