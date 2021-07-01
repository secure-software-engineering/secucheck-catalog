package de.fraunhofer.iem.secucheck.specifications.CWE78;

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
 * CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)
 * <p>
 * The software constructs all or part of an OS command using externally-influenced
 * input from an upstream component, but it does not neutralize or incorrectly
 * neutralizes special elements that could modify the intended OS command
 * when it is sent to a downstream component.
 */
@FluentTQLSpecificationClass
public class OsCommandInjection_AlternativeSpec implements FluentTQLUserInterface {

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
            .atClass("de.fraunhofer.iem.secucheck.todolist.controllers.NewTaskController")
            .returns("java.lang.String")
            .named("correctFileName")
            .accepts("java.lang.String")
            .configure();
    public Method sanitizerMethod = new MethodConfigurator(sanitizerMethodSign)
            .in().param(0)
            .out().returnValue()
            .configure();

    /**
     * Sink
     */
    public MethodSignature sinkMethodSign = new MethodSignatureConfigurator()
            .atClass("de.fraunhofer.iem.secucheck.todolist.service.DirectoryStorageService")
            .returns("int")
            .named("getFileSizeOnSystem")
            .accepts("de.fraunhofer.iem.secucheck.todolist.model.Task,java.lang.String")
            .configure();
    public Method sinkMethod = new MethodConfigurator(sinkMethodSign)
            .in().param(0)
            .configure();

    /**
     * Sink
     */
    public MethodSignature sinkMethod2Sign = new MethodSignatureConfigurator()
            .atClass("de.fraunhofer.iem.secucheck.todolist.service.DirectoryStorageService")
            .returns("java.lang.String")
            .named("store")
            .accepts("org.springframework.web.multipart.MultipartFile,de.fraunhofer.iem.secucheck.todolist.model.Task,java.lang.String")
            .configure();
    public Method sinkMethod2 = new MethodConfigurator(sinkMethod2Sign)
            .in().param(1)
            .configure();

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specifications
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE78_OsCommandInjection_TF1_WithMethodSign")
                .from(sourceMethod)
                .notThrough(sanitizerMethod)
                .to(sinkMethod)
                .report("CWE-78 detected: 'OS Command Injection' from untrusted value 'Task newTask'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        TaintFlowQuery myTF2 = new TaintFlowQueryBuilder("CWE78_OsCommandInjection_TF2_WithMethodSign")
                .from(sourceMethod)
                .notThrough(sanitizerMethod)
                .to(sinkMethod2)
                .report("CWE-78 detected: 'OS Command Injection' from untrusted value 'Task newTask'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);
        myFluentTQLSpecs.add(myTF2);

        return myFluentTQLSpecs;
    }

}
