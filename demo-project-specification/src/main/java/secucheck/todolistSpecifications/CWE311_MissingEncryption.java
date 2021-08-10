package secucheck.todolistSpecifications;

import secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * CWE-311: Missing Encryption of Sensitive Data
 * <p>
 * The software does not encrypt sensitive or critical information before storage or transmission.
 */
@FluentTQLSpecificationClass
public class CWE311_MissingEncryption implements FluentTQLUserInterface {

    /**
     * Source
     */
    public Method sourceMethod = new MethodConfigurator(
            "secucheck.todolist.controllers.NewTaskController: " +
                    "java.lang.String saveTask(" +
                    "secucheck.todolist.model.Task," +
                    "org.springframework.web.multipart.MultipartFile," +
                    "org.springframework.web.servlet.mvc.support.RedirectAttributes)")
            .out().param(0)
            .configure();

    /**
     * Sanitizer
     */
    public Method sanitizerMethod = new MethodConfigurator("secucheck.todolist.controllers.TaskController: " +
            "java.lang.String encrypt(" +
            "java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    /**
     * Sink
     */
    public Method sinkMethod = new MethodConfigurator(
            "secucheck.todolist.repository.TaskRepository: java.lang.Object save(java.lang.Object)")
            .in().param(0)
            .configure();

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specifications
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE311_MissingEncryption")
                .from(sourceMethod)
                .to(sinkMethod)
                .report("CWE-311 detected: Missing Encryption of Sensitive Data from 'Task newTask'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }
}