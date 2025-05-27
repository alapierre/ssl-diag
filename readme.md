# SSL Diagnostic tool

````shell
java -jar target/ssl-diag-1.0-SNAPSHOT.jar https://google.pl
````

## Adding CA cert into the JAVA trust store

````shell
keytool -importcert -alias Entrust_Root_G2 -file Entrust_Root_Certification_Authority_G2.cer -storepass changeit -cacerts -noprompt
````

> be sure that you use the right path to keet tool— it has to be in the same path as your `JAVA_HOME`. 

## List trust certs

````shell
keytool -list -storepass changeit -v -cacerts
````