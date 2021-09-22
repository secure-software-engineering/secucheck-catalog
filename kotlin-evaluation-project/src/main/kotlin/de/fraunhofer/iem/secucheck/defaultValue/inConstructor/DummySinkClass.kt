package de.fraunhofer.iem.secucheck.defaultValue.inConstructor

/**
 * A Dummy class that has the default value in its constructor to evaluate the SecuCheck-Kotlin can handle default value
 * constructor in Kotlin
 *
 * @author Ranjith Krishnamurthy
 */
class DummySinkClass(
    private val data1: String = "",
    private val data2: String = "",
    private val data3: String = "",
    private val data4: String = ""
) {
    fun printData() {
        println(data1)
        println(data2)
        println(data3)
        println(data4)
    }
}