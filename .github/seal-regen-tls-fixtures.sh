#!/usr/bin/env bash
# Seal Security: regenerate the TLS test fixtures under test/org/apache/tomcat/util/net/.
# user1.jks (the mTLS client cert) expired 2025-08-15, so every client-cert suite
# (TestClientCert, TestSsl, TestCustomSslTrustManager, ...) fails its handshake. The CA
# private key is not in the repo, so the whole chain (CA + localhost RSA/EC + user1) is
# re-issued with the same shapes, aliases and passwords TesterSupport.java hard-codes.
# These files never enter the jar. .jks are binary, so this runs at CI time instead of
# being committed.
set -euo pipefail
CERTDIR="${1:-test/org/apache/tomcat/util/net}"
CERTWORK=$(mktemp -d)

cat > "$CERTWORK/ca.cnf" <<'CACNF'
[req]
distinguished_name = dn
prompt = no
x509_extensions = v3_ca
[dn]
C  = US
ST = MA
L  = Wakefield
O  = The Apache Software Foundation
OU = Apache Tomcat PMC
CN = Apache Tomcat Test CA
[v3_ca]
basicConstraints = CA:TRUE
subjectKeyIdentifier = hash
CACNF

cat > "$CERTWORK/localhost.ext" <<'LHEXT'
basicConstraints = CA:FALSE
nsComment = "OpenSSL Generated Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = DNS:localhost,IP:127.0.0.1
LHEXT

cat > "$CERTWORK/user1.ext" <<'U1EXT'
basicConstraints = CA:FALSE
nsComment = "OpenSSL Generated Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
keyUsage = digitalSignature,nonRepudiation,keyEncipherment
U1EXT

# Leaf DN prefix: C=US, ST=DE, L=Wilmington, O=..., OU=..., CN=<name> -- as shipped.
LEAF_DN="/C=US/ST=DE/L=Wilmington/O=The Apache Software Foundation/OU=Apache Tomcat PMC/CN="

# The CA (self-signed, 4096-bit RSA).
openssl req -x509 -new -nodes -newkey rsa:4096 -sha256 -days 7300 \
    -config "$CERTWORK/ca.cnf" -keyout "$CERTWORK/ca-key.pem" -out "$CERTWORK/ca-cert.pem"

# localhost RSA leaf: 2048-bit, PKCS#8 key file (matches the shipped "BEGIN PRIVATE KEY").
openssl genrsa -out "$CERTWORK/rsa-pkcs1.pem" 2048
openssl pkcs8 -topk8 -nocrypt -in "$CERTWORK/rsa-pkcs1.pem" -out "$CERTWORK/localhost-rsa-key.pem"
openssl req -new -key "$CERTWORK/localhost-rsa-key.pem" -subj "${LEAF_DN}localhost" -out "$CERTWORK/rsa.csr"
openssl x509 -req -in "$CERTWORK/rsa.csr" -CA "$CERTWORK/ca-cert.pem" -CAkey "$CERTWORK/ca-key.pem" \
    -CAcreateserial -days 7300 -sha256 -extfile "$CERTWORK/localhost.ext" -out "$CERTWORK/localhost-rsa.crt"

# localhost EC leaf: secp256r1, SEC1 key file preceded by EC PARAMETERS (as shipped).
openssl ecparam -name prime256v1 -genkey -noout -out "$CERTWORK/ec-sec1.pem"
{ openssl ecparam -name prime256v1; cat "$CERTWORK/ec-sec1.pem"; } > "$CERTWORK/localhost-ec-key.pem"
openssl req -new -key "$CERTWORK/localhost-ec-key.pem" -subj "${LEAF_DN}localhost" -out "$CERTWORK/ec.csr"
openssl x509 -req -in "$CERTWORK/ec.csr" -CA "$CERTWORK/ca-cert.pem" -CAkey "$CERTWORK/ca-key.pem" \
    -CAcreateserial -days 7300 -sha256 -extfile "$CERTWORK/localhost.ext" -out "$CERTWORK/localhost-ec.crt"

# user1 client leaf: 2048-bit RSA. TesterSupport.configureClientCertContext() reads this
# cert's subject DN out of the keystore at run time and registers exactly that string with
# TesterMapRealm, so the DN only has to be self-consistent -- no test hard-codes it.
openssl genrsa -out "$CERTWORK/user1-pkcs1.pem" 2048
openssl pkcs8 -topk8 -nocrypt -in "$CERTWORK/user1-pkcs1.pem" -out "$CERTWORK/user1-key.pem"
openssl req -new -key "$CERTWORK/user1-key.pem" -subj "${LEAF_DN}user1" -out "$CERTWORK/user1.csr"
openssl x509 -req -in "$CERTWORK/user1.csr" -CA "$CERTWORK/ca-cert.pem" -CAkey "$CERTWORK/ca-key.pem" \
    -CAcreateserial -days 7300 -sha256 -extfile "$CERTWORK/user1.ext" -out "$CERTWORK/user1.crt"

# keytool cannot import a private key directly, so each PrivateKeyEntry goes through a
# PKCS12 staging file. Passing -certfile produces the 2-cert chain; omitting it leaves the
# leaf alone, which is how localhost-rsa-copy1.jks and localhost-ec.jks ship.
mk_jks() {
    local keyf="$1" certf="$2" chainf="$3" jks_alias="$4" out="$5" keypass="$6"
    local p12="$CERTWORK/${jks_alias}.$(basename "$out").p12"
    if [ -n "$chainf" ]; then
        openssl pkcs12 -export -name "$jks_alias" -inkey "$keyf" -in "$certf" -certfile "$chainf" \
            -out "$p12" -passout pass:changeit
    else
        openssl pkcs12 -export -name "$jks_alias" -inkey "$keyf" -in "$certf" \
            -out "$p12" -passout pass:changeit
    fi
    rm -f "$out"
    keytool -importkeystore -noprompt \
        -srckeystore "$p12" -srcstoretype PKCS12 -srcstorepass changeit -srcalias "$jks_alias" \
        -destkeystore "$out" -deststoretype JKS -deststorepass changeit \
        -destalias "$jks_alias" -destkeypass "$keypass"
}

# ca.jks holds the CA as a trustedCertEntry (no private key) -- TesterSupport uses it as
# the truststore and reads alias "ca" to derive the expected client-auth issuer.
rm -f "$CERTDIR/ca.jks"
keytool -importcert -noprompt -alias ca -file "$CERTWORK/ca-cert.pem" \
    -keystore "$CERTDIR/ca.jks" -storetype JKS -storepass changeit

mk_jks "$CERTWORK/localhost-rsa-key.pem" "$CERTWORK/localhost-rsa.crt" "$CERTWORK/ca-cert.pem" \
    tomcat "$CERTDIR/localhost-rsa.jks" changeit
mk_jks "$CERTWORK/localhost-rsa-key.pem" "$CERTWORK/localhost-rsa.crt" "" \
    tomcat "$CERTDIR/localhost-rsa-copy1.jks" tomcatpass
mk_jks "$CERTWORK/localhost-ec-key.pem" "$CERTWORK/localhost-ec.crt" "" \
    tomcat "$CERTDIR/localhost-ec.jks" changeit
mk_jks "$CERTWORK/user1-key.pem" "$CERTWORK/user1.crt" "$CERTWORK/ca-cert.pem" \
    user1 "$CERTDIR/user1.jks" changeit

# PEM forms. ca-cert.pem is a bare PEM block; the two *-cert.pem leaves ship as an
# `openssl x509 -text` dump followed by the PEM block, which is what `-text` emits.
cp "$CERTWORK/ca-cert.pem"           "$CERTDIR/ca-cert.pem"
cp "$CERTWORK/localhost-rsa-key.pem" "$CERTDIR/localhost-rsa-key.pem"
cp "$CERTWORK/localhost-ec-key.pem"  "$CERTDIR/localhost-ec-key.pem"
openssl x509 -in "$CERTWORK/localhost-rsa.crt" -text > "$CERTDIR/localhost-rsa-cert.pem"
openssl x509 -in "$CERTWORK/localhost-ec.crt"  -text > "$CERTDIR/localhost-ec-cert.pem"
chmod 644 "$CERTDIR"/*.jks "$CERTDIR"/*.pem

# Fail loudly if the new chain does not validate or a keystore came out wrong.
openssl verify -CAfile "$CERTDIR/ca-cert.pem" "$CERTDIR/localhost-rsa-cert.pem"
openssl verify -CAfile "$CERTDIR/ca-cert.pem" "$CERTDIR/localhost-ec-cert.pem"
keytool -list -v -keystore "$CERTDIR/localhost-rsa.jks"       -storepass changeit -alias tomcat -keypass changeit
keytool -list -v -keystore "$CERTDIR/localhost-rsa-copy1.jks" -storepass changeit -alias tomcat -keypass tomcatpass
keytool -list -v -keystore "$CERTDIR/localhost-ec.jks"        -storepass changeit -alias tomcat -keypass changeit
keytool -list -v -keystore "$CERTDIR/user1.jks"               -storepass changeit -alias user1  -keypass changeit
keytool -list -v -keystore "$CERTDIR/ca.jks"                  -storepass changeit -alias ca
rm -rf "$CERTWORK"
