package secucheck.catalogSpecifications.FluentTQLSpecifications.PathTraversalAttack.CWE22;

import secucheck.catalogSpecifications.FuentTQLRepositories.Sources.ServletSources;
import secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import secucheck.InternalFluentTQL.dsl.MethodSelector;
import secucheck.InternalFluentTQL.dsl.QueriesSet;
import secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import secucheck.InternalFluentTQL.dsl.annotations.*;
import secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * Internal FluentTQL specification for Path-Traversal attack.
 *
 */
@FluentTQLSpecificationClass
@ImportAndProcessOnlyStaticFields(classList = {ServletSources.class})
public class PathTraversalAttackSpec implements FluentTQLUserInterface {
    /**
     * This is a user defined sanitizer for avoiding path traversal attack. This is not recommended to use this method. This is for example.
     */
    @InFlowParam(parameterID = {0})
    @OutFlowReturnValue
    public Method sanitizer = new MethodSelector("secucheck.InternalFluentTQL.catalog.PathTraversalAttack.CWE22.PathTraversal: java.lang.String sanitizeForPATH(java.lang.String)");

    /**
     * This is a required propagator that is used in the second taint flow to achieve path traversal attack.
     */
    @InFlowParam(parameterID = {0})
    @OutFlowThisObject
    public Method requiredPropagator = new MethodSelector("java.io.File: void <init>(java.lang.String)");

    /**
     * This is the sink in first taint flow where File constructor is not used.
     */
    @InFlowParam(parameterID = {0})
    public Method sink1 = new MethodSelector("java.io.FileInputStream: void <init>(java.lang.String)");

    /**
     * This is the sink for second taint flow where File constructor is used as a required propagator.
     */
    @InFlowParam(parameterID = {0})
    public Method sink2 = new MethodSelector("java.io.FileInputStream: void <init>(java.io.File)");

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specification
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        /*
         * This is the first taint flow that achieves path traversal attack.
         */
        TaintFlowQuery tf1 = new TaintFlowQueryBuilder("PathTraversal_TF1")
                .from(ServletSources.servletSources)
                .notThrough(sanitizer)
                .to(sink1)
                .report("Path traversal - CWE22!")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        TaintFlowQuery tf2 = new TaintFlowQueryBuilder("PathTraversal_TF2")
                .from(ServletSources.servletSources)
                .notThrough(sanitizer)
                .through(requiredPropagator)
                .to(sink2)
                .report("Path traversal attack through File constructor - CWE22!")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        //TaintFlowSet for path traversal attack that contains the above both taint flows that achieves path traversal attack.
        QueriesSet pathTraversalTFSet = new QueriesSet("pathTraversalTFSet")
                .addTaintFlowQuery(tf1)
                .addTaintFlowQuery(tf2);

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(pathTraversalTFSet);

        return myFluentTQLSpecs;
    }
}
