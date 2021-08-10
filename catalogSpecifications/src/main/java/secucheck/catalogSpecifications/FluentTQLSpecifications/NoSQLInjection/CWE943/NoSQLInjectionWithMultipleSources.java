package secucheck.catalogSpecifications.FluentTQLSpecifications.NoSQLInjection.CWE943;

import secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import secucheck.InternalFluentTQL.dsl.MethodSelector;
import secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import secucheck.InternalFluentTQL.dsl.annotations.InFlowParam;
import secucheck.InternalFluentTQL.dsl.annotations.OutFlowReturnValue;
import secucheck.InternalFluentTQL.dsl.annotations.OutFlowThisObject;
import secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * Internal FluentTQL specification for No-SQL-Injection with multiple sources.
 *
 */
@FluentTQLSpecificationClass
public class NoSQLInjectionWithMultipleSources implements FluentTQLUserInterface {
    /**
     * First source that takes userName from the user.
     */
    @OutFlowReturnValue
    public Method source1 = new MethodSelector("secucheck.InternalFluentTQL.catalog.NoSQLInjection.CWE943.NoSQLInjectionWithTwoSources: java.lang.String getUserName()");

    /**
     * Second source that takes old password from the user.
     */
    @OutFlowReturnValue
    public Method source2 = new MethodSelector("secucheck.InternalFluentTQL.catalog.NoSQLInjection.CWE943.NoSQLInjectionWithTwoSources: java.lang.String getOldPassword()");

    /**
     * Third souce that takes new password from the user.
     */
    @OutFlowReturnValue
    public Method source3 = new MethodSelector("secucheck.InternalFluentTQL.catalog.NoSQLInjection.CWE943.NoSQLInjectionWithTwoSources: java.lang.String getNewPassword()");

    /**
     * sanitizeForMongoDB is user defined simple sanitizer for mongodb.
     */
    @InFlowParam(parameterID = {0})
    @OutFlowReturnValue
    public Method sanitizer = new MethodSelector("secucheck.InternalFluentTQL.catalog.NoSQLInjection.CWE943.NoSQLInjectionWithTwoSources: java.lang.String sanitizeForMongoDB(java.lang.String)");

    /**
     * put is a method that the data flow has to go through after sanitizer to form a filer to update the password.
     * If the data flow goes through this method before sanitizer then there will be a security vulnerability.
     */
    @InFlowParam(parameterID = {1})
    @OutFlowThisObject
    public Method requiredPropagator1 = new MethodSelector("com.mongodb.BasicDBObject: java.lang.Object put(java.lang.Object,java.lang.Object)");

    /**
     * This put is a method that the data flow has to go through after sanitizer to form a new BasicDBObject password to update the password in mongodb.
     * If the data flow goes through this method before sanitizer then there will be a security vulnerability.
     */
    @InFlowParam(parameterID = {1})
    @OutFlowThisObject
    public Method requiredPropagator2 = new MethodSelector("com.mongodb.BasicDBObject: com.mongodb.BasicDBObject put(java.lang.String,com.mongodb.BasicDBObject)");

    /**
     * updateOne is a sink that updates the password.
     */
    @InFlowParam(parameterID = {0, 1})
    public Method sink = new MethodSelector("com.mongodb.client.MongoCollection: com.mongodb.client.result.UpdateResult updateOne(org.bson.conversions.Bson,org.bson.conversions.Bson)");

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specification
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery noSQLWithMultipleSourcesSpec = new TaintFlowQueryBuilder("NoSQLiWithMultipleSources")
                .from(source1).notThrough(sanitizer).through(requiredPropagator1).to(sink)
                .and()
                .from(source2).notThrough(sanitizer).through(requiredPropagator1).to(sink)
                .and()
                .from(source3).notThrough(sanitizer).through(requiredPropagator1).to(sink)
                .report("There is a No-SQL-Injection (CWE943) with multiple sources")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(noSQLWithMultipleSourcesSpec);

        return myFluentTQLSpecs;
    }
}
