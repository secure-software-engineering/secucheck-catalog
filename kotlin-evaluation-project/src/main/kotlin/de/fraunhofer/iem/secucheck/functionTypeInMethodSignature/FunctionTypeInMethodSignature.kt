package de.fraunhofer.iem.secucheck.functionTypeInMethodSignature

/**
 * Dummy propagator that takes the function as parameter
 *
 * @author Ranjith Krishnamurthy
 */
fun propagate(message: String, propagator: (String, Boolean) -> String): String = propagator(message, true)

/**
 * Dummy sanitizer that takes the function as parameter
 *
 * @author Ranjith Krishnamurthy
 */
fun sanitize(message: String, sanitizer: (String) -> String): String = sanitizer(message)

/**
 * Dummy source that takes the function as parameter
 *
 * @author Ranjith Krishnamurthy
 */
fun source(generateSecret: () -> String): String = generateSecret()

/**
 * Dummy sink that takes the function as parameter
 *
 * @author Ranjith Krishnamurthy
 */
fun sink(secret: String) = println(secret)

/**
 * Dummy function where the taintflow is present
 *
 * @author Ranjith Krishnamurthy
 */
fun entryPointWithTaintFlow() {
    val taintedData = source { "SECRET" }

    val intermediateData = propagate(taintedData) { message, append ->
        if (append)
            "PROPAGATOR $message"
        else
            message
    }

    sink(intermediateData)
}

/**
 * Dummy function where the taintflow is not present
 *
 * @author Ranjith Krishnamurthy
 */
fun entryPointWithOutTaintFlow() {
    val taintedData = source { "SECRET" }

    val intermediateData = propagate(taintedData) { message, append ->
        if (append)
            "PROPAGATOR $message"
        else
            message
    }

    val sanitizedIntermediateData = sanitize(intermediateData) { message ->
        "ENCRYPTED_DATA"
    }

    sink(sanitizedIntermediateData)
}