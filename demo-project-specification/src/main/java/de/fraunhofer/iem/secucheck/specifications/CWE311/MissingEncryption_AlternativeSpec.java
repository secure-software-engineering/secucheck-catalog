package de.fraunhofer.iem.secucheck.specifications.CWE311;

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
 * CWE-311: Missing Encryption of Sensitive Data
 * <p>
 * The software does not encrypt sensitive or critical information before storage or transmission.
 */
@FluentTQLSpecificationClass
public class MissingEncryption_AlternativeSpec implements FluentTQLUserInterface {

    /**
     * Source
     */
    public MethodSignature sourceMethodSign = new MethodSignatureConfigurator()
            .atClass("de.fraunhofer.iem.secucheck.todolist.controllers.NewTaskController")
            .returns("java.lang.String")
            .named("saveTask")
            .accepts("de.fraunhofer.iem.secucheck.todolist.model.Task,org.springframework.web.multipart.MultipartFile,org.springframework.web.servlet.mvc.support.RedirectAttributes")
            .configure();
    public Method sourceMethod = new MethodConfigurator(sourceMethodSign)
            .out().param(0)
            .configure();

    /**
     * Sanitizer
     */
    public MethodSignature sanitizerMethodSign = new MethodSignatureConfigurator()
            .atClass("de.fraunhofer.iem.secucheck.todolist.controllers.TaskController")
            .returns("java.lang.String")
            .named("encrypt")
            .accepts("java.lang.String")
            .configure();
    public Method sanitizerMethod = new MethodConfigurator(sanitizerMethodSign)
            .in().param(0)
            .out().returnValue()
            .configure();

    /**
     * Sink
     */
    public Method sinkMethod = new MethodConfigurator(
            "de.fraunhofer.iem.secucheck.todolist.repository.TaskRepository: java.lang.Object save(java.lang.Object)")
            .in().param(0)
            .configure();

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specifications
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE311_MissingEncryption_WithMethodSign")
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
