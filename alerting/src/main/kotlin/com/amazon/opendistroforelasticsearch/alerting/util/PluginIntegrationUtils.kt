package com.amazon.opendistroforelasticsearch.alerting.util

import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate


fun getTrustStore(file: String): KeyStore? {
    val certificates = loadCertificatesFromFile(file)
    return toTruststore("node-cert", certificates)
}

@Throws(Exception::class)
fun loadCertificatesFromFile(file: String): Array<X509Certificate>? {
    if (file == null) {
        return null
    }

    val fact = CertificateFactory.getInstance("X.509")
    val x509Certs = mutableListOf<X509Certificate>()
    Files.newInputStream(Path.of(file)).use {stream ->
        try {
            val certs = fact.generateCertificates(stream)
            certs.forEach { cert -> x509Certs.add(cert as X509Certificate) }
        } catch(e: Exception) {
            throw e
        }
    }
    return x509Certs.toTypedArray()
}

@Throws(Exception::class)
fun toTruststore(trustCertificatesAliasPrefix: String, trustCertificates: Array<X509Certificate>?): KeyStore? {
    if (trustCertificates == null) {
        return null
    } else {
        val ks = KeyStore.getInstance("JKS")
        ks.load(null)
        if (trustCertificates != null && trustCertificates.isNotEmpty()) {
            for (i in trustCertificates.indices) {
                ks.setCertificateEntry(trustCertificatesAliasPrefix + "_" + i, trustCertificates[i])
            }
        }
        return ks
    }
}
