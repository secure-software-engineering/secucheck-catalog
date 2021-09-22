package de.fraunhofer.iem.secucheck.dataTypeTransformer.classLevel

/**
 * Dummy class that has a dummy source method with the Kotlin's type to evaluate the
 * SecuCheck-Kotlin can handle the Kotlin's data type without user's work around
 *
 * @author Ranjith Krishnamurthy
 */
class DummySource {
    fun generateSecret(age: Int, name: String, lst: List<String>): String = "$name:$age:${lst.size}"

    fun propagateEverything(incoming: String): String = "PROPAGATE = $incoming"
}