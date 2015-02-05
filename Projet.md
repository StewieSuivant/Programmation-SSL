Poodle
======

Faille
------

* Révélé par Google dans un rapport rendu public le 14 octobre 2014.
* Vulnérabilité logicielle présente dans le protocole SSL 3.0.
* Permet de déchiffrer les infos entre le browser de la victime et le serveur sécurisé, via un MITM.
* Provoque une érreur lors d'une communication chiffrée par TLS forçant le basculement sur SSL 3.0.

Lors de du handshake entre le client et le serveur, il y'a une négociation pour désigner quelle version du protocole sera utilisé. La version la plus récente commune aux 2 est normalemet utilisé.  
Cependant, un déclassement de version peut se faire suite à un problème réseau ou à un attanquant actif. Ainsi, le handshake est sensible à un MITM.



Sécurité
--------

* Pour se prémunir de cette attaque, migrer les serveurs en TLS.
* Le 8/12/14, l'entreprise de sécurité Qualys déclare avoir réussi à toucher TLS avec cette même vulnérabilité. Il est estimé qu'au moins 10% des matériels seraient touchés.
* ajouter le support de *TLS_FALLBACK_SCSV* pour les administrateur web. Cela bloque la possibilité pour l'attaquant de contraindre l'utilisation de SSL v3.
* Paramétrage du browser pour éviter la faille : 
	* Firefox : dans l'URL => *about:config*, mettre *security.tls.version.min* à **1**.
	* IE : ne pas cocher SSL v3.
	* Chrome : ajouter un commutateur dans le raccourci.
* Ne pas se connecter à des point d'accés wifi gratuit.

Sources
-------

* [Wikipedia](http://fr.wikipedia.org/wiki/POODLE)
* [Google : Online secure blog](http://googleonlinesecurity.blogspot.com.au/2014/10/this-poodle-bites-exploiting-ssl-30.html)
* [Rapport](https://www.openssl.org/~bodo/ssl-poodle.pdf "Rapport de google du 14 septembre 2014")
* [Adam langley's blog](https://www.imperialviolet.org/2014/10/14/poodle.html)

* [best](https://www.imperialviolet.org/2014/10/14/poodle.html)
* [best](https://www.openssl.org/~bodo/ssl-poodle.pdf)


BERserk
=======

Faille
------
* 29 septembre 2014
* La vulnérabilité permet à un attaquant de forger une signature RSA, qui va lui permettre de bypasser l'authentification à un site sécurisé.
* This is a variant of Daniel Bleichenbacher’s PKCS#1 v1.5 RSA Signature Forgery vulnerability (CVE-2006-4339, http://www.imc.org/ietf-openpgp/mail-archive/msg06063.html).

Sécurité
--------



Sources
-------
* [Wikipedia](http://en.wikipedia.org/wiki/Transport_Layer_Security#Attacks_against_TLS.2FSSL)
* [Intel security](http://www.intelsecurity.com/advanced-threat-research/berserk.html "ATR : Advanced Threat Research ")
* [Intel security rapport](http://www.intelsecurity.com/resources/wp-berserk-analysis-part-1.pdf)
* [Bleichenbacher](http://www.ssi.gouv.fr/IMG/pdf/SSL_TLS_etat_des_lieux_et_recommandations.pdf)


OpenSSL
=======

Sources
-------
[OpenSSL.org](https://www.openssl.org/)
[prog. SSL enib](http://www.enib.fr/~harrouet/Data/Courses/SSL_HTTPS.pdf)

---------------------------------------------------------------------------------------------------------------------


Programmation SSL
=====================


Outillage
---------

* OpenSSL : contitent la librairie nécessaire pour la prog. openssl. (apt-get install opensss)
* certtool : permet de créer des cleé privées et des certificats. (apt-get install gnutls-bin)


Création des clés et certificats nécessaires
--------------------------------------------

### Sources

* Pour créer un CA et des certificats X509, c'est par [ici](http://www.ultrabug.fr/wiki/index.php5?title=Cr%C3%A9er_un_CA_et_des_certificats_X509_avec_l%27outil_certtool_de_GnuTLS)
