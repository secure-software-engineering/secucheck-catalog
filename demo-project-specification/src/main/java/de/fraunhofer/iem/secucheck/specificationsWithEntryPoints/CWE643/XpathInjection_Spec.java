package de.fraunhofer.iem.secucheck.specificationsWithEntryPoints.CWE643;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodEntryPoint;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.EntryPoint.EntryPoint;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * CWE-643: Improper Neutralization of Data within XPath Expressions (XPath Injection)
 * <p>
 * The software uses external input to dynamically construct an XPath expression used
 * to retrieve data from an XML database, but it does not neutralize or incorrectly
 * neutralizes that input. This allows an attacker to control the structure of the query.
 */
@FluentTQLSpecificationClass
public class XpathInjection_Spec implements FluentTQLUserInterface {

    /**
     * Sources
     */
    public Method source1 = new MethodConfigurator("javax.servlet.http.HttpServletRequest: java.lang.String getParameter(java.lang.String)")
            .out().returnValue()
            .configure();

    public Method source2 = new MethodConfigurator(
            "javax.servlet.ServletRequest: java.lang.String[] getParameterValues(java.lang.String)")
            .out().returnValue()
            .configure();

    /**
     * Sink
     */
    public Method sink1 = new MethodConfigurator("javax.xml.xpath.XPath: javax.xml.xpath.XPathExpression compile(java.lang.String)")
            .in().param(0)
            .configure();

    /**
     * Entry Point
     */
    String methodEntryPointName = "de.fraunhofer.iem.secucheck.todolist.controllers.PasswordController: "
    		+ "java.lang.String "
    		+ "updatePassword "
    		+ "(javax.servlet.http.HttpServletRequest, "
    		+ "javax.servlet.http.HttpServletResponse)";
    public MethodEntryPoint entryPoint = new MethodEntryPoint(methodEntryPointName);
    public List<EntryPoint> entryPoints = Arrays.asList(entryPoint);

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specifications
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE643_XpathInjection_TF1_WithEntryPoints")
                .atOnlyDSLEntryPoints(entryPoints)
        		.from(source1)
                .to(sink1)
                .report("CWE-634 detected: XPath Injection from untrusted value 'getPartameter()'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        TaintFlowQuery myTF2 = new TaintFlowQueryBuilder("CWE643_XpathInjection_TF2_WithEntryPoints ")
                .atOnlyDSLEntryPoints(entryPoints)
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
