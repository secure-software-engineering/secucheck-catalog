package de.fraunhofer.iem.secucheck.specifications.CWE643;

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
 * CWE-643: Improper Neutralization of Data within XPath Expressions (XPath Injection)
 * <p>
 * The software uses external input to dynamically construct an XPath expression used
 * to retrieve data from an XML database, but it does not neutralize or incorrectly
 * neutralizes that input. This allows an attacker to control the structure of the query.
 */
@FluentTQLSpecificationClass
public class XpathInjection_AlternativeSpec implements FluentTQLUserInterface {

    /**
     * Sources
     */
    public MethodSignature source1Sign = new MethodSignatureConfigurator()
            .atClass("javax.servlet.http.HttpServletRequest")
            .returns("java.lang.String")
            .named("getParameter")
            .accepts("java.lang.String")
            .configure();
    public Method source1 = new MethodConfigurator(source1Sign)
            .out().returnValue()
            .configure();

    public MethodSignature source2Sign = new MethodSignatureConfigurator()
            .atClass("javax.servlet.ServletRequest")
            .returns("java.lang.String[]")
            .named("getParameterValues")
            .accepts("java.lang.String")
            .configure();
    public Method source2 = new MethodConfigurator(source2Sign)
            .out().returnValue()
            .configure();

    /**
     * Sink
     */
    public MethodSignature sink1Sign = new MethodSignatureConfigurator()
            .atClass("javax.xml.xpath.XPath")
            .returns("javax.xml.xpath.XPathExpression")
            .named("compile")
            .accepts("java.lang.String")
            .configure();
    public Method sink1 = new MethodConfigurator(sink1Sign)
            .in().param(0)
            .configure();


    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specifications
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE643_XpathInjection_TF1_WithMethodSign")
                .from(source1)
                .to(sink1)
                .report("CWE-634 detected: XPath Injection from untrusted value 'getPartameter()'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        TaintFlowQuery myTF2 = new TaintFlowQueryBuilder("CWE643_XpathInjection_TF2_WithMethodSign")
                .from(source2)
                .to(sink1)
                .report("CWE-634 detected: XPath Injection from untrusted value 'getParameterValues()'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);
        myFluentTQLSpecs.add(myTF2);

        return myFluentTQLSpecs;
    }

}
