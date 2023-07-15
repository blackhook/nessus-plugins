##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:5894. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163916);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/02");

  script_cve_id("CVE-2021-44906", "CVE-2022-24823", "CVE-2022-25647");
  script_xref(name:"RHSA", value:"2022:5894");

  script_name(english:"RHEL 9 : Red Hat  JBoss Enterprise Application Platform 7.4.6 Security update. (Moderate) (RHSA-2022:5894)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:5894 advisory.

  - minimist: prototype pollution (CVE-2021-44906)

  - netty: world readable temporary file containing sensitive data (CVE-2022-24823)

  - com.google.code.gson-gson: Deserialization of Untrusted Data in com.google.code.gson-gson (CVE-2022-25647)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-44906");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24823");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25647");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:5894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2066009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2080850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2087186");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44906");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 378, 379, 400, 502, 1321);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-FastInfoset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-core-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-dto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-hornetq-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-hqclient-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-jdbc-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-jms-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-jms-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-journal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-ra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-service-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-aesh-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-aesh-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-agroal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-agroal-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-agroal-narayana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-agroal-pool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-lang2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-xjc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-mime4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-sshd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-native-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-wildfly-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-atinject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-avro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-azure-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-pkix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-byte-buddy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-caffeine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cal10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-core-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-mapper-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-xc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cryptacular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-boolean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-bug986");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-dom4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ecj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-eclipse-jgit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-fge-btf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-fge-msg-simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-concurrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-fastinfoset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jaf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-gnu-getopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-gson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-guava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-guava-failureaccess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-guava-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-h2database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-beanvalidation-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-backend-jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-backend-jms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-orm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-serialization-avro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-validator-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hornetq-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hornetq-core-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hornetq-jms-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-httpcomponents-asyncclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-httpcomponents-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-component-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-v53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-deployers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-istack-commons-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-istack-commons-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-coreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jsr310");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-modules-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-modules-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jakarta-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jakarta-security-enterprise-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jandex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jasypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-java-classmate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-javaee-jpa-spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-javaee-security-soteria");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-javaee-security-soteria-enterprise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-javaewah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-javapackages-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxb-jxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxb-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxb-xjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxbintros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jcip-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jctools-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jettison");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jgroups-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jgroups-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-joda-time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-json-patch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jsonb-spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jul-to-slf4j-stub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-analyzers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-backward-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-facet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-queries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-queryparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-mustache-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-mustache-java-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-compensations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-idlj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-txframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-neethi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-buffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-mqtt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-smtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-socks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-stomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-handler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-handler-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-resolver-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-resolver-dns-classes-macos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-tcnative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-classes-epoll");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-classes-kqueue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-native-epoll");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-native-unix-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-rxtx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-sctp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-udt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-xnio-transport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-objectweb-asm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-profile-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-saml-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-saml-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-security-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-security-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-soap-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-xacml-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-xacml-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-xacml-saml-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-xacml-saml-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-xmlsec-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-xmlsec-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-simple-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-wildfly8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-protostream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-python3-javapackages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-reactive-streams");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-reactivex-rxjava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-reactivex-rxjava2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-relaxng-datatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-atom-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jackson-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jackson2-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jaxb-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jettison-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jose-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jsapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-binding-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-p-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-multipart-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-rxjava2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-spring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-validator-provider-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-yaml-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-rngom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-shibboleth-java-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-slf4j-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-slf4j-ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-snakeyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-stax-ex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-stax2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-staxmapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-sun-istack-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-sun-saaj-1.3-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-sun-saaj-1.4-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-sun-ws-metadata-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-taglibs-standard-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-taglibs-standard-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-taglibs-standard-spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-jastow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-vdx-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-vdx-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-velocity-engine-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-cdi-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-jta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-probe-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-client-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-discovery-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-naming-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-naming-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-el9-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-woodstox-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ws-commons-XmlSchema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wsdl4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-policy-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xml-commons-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xml-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xml-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xsom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-yasson");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/jbeap/7.4/debug',
      'content/dist/layered/rhel9/x86_64/jbeap/7.4/os',
      'content/dist/layered/rhel9/x86_64/jbeap/7.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-1-18.el9eap', 'cpu':'x86_64', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-cli-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-commons-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-core-client-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-dto-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-hornetq-protocol-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-hqclient-protocol-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jdbc-store-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jms-client-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jms-server-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-journal-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-native-1.0.2-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-ra-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-selector-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-server-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-service-extensions-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-tools-2.16.0-9.redhat_00042.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-aesh-extensions-1.8.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-aesh-readline-2.2.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-agroal-1.3.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-agroal-api-1.3.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-agroal-narayana-1.3.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-agroal-pool-1.3.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-antlr-2.7.7-54.redhat_7.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-commons-beanutils-1.9.4-1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-commons-cli-1.4.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-commons-codec-1.15.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-commons-collections-3.2.2-9.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-commons-io-2.10.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-commons-lang-3.11.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-commons-lang2-2.6.0-1.redhat_7.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-3.3.13-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-rt-3.3.13-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-services-3.3.13-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-tools-3.3.13-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-xjc-utils-3.3.1-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-mime4j-0.6.0-4.1.redhat_7.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-sshd-2.7.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-artemis-native-1.0.2-3.redhat_1.el9eap', 'cpu':'x86_64', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap7-jboss'},
      {'reference':'eap7-artemis-native-wildfly-1.0.2-3.redhat_1.el9eap', 'cpu':'x86_64', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap7-jboss'},
      {'reference':'eap7-artemis-wildfly-integration-1.0.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-atinject-1.0.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-avro-1.7.6-7.1.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-azure-storage-8.6.6-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-bouncycastle-1.68.0-2.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-bouncycastle-mail-1.68.0-2.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-bouncycastle-pg-1.68.0-2.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-bouncycastle-pkix-1.68.0-2.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-bouncycastle-prov-1.68.0-2.redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-byte-buddy-1.11.12-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-caffeine-2.8.8-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-cal10n-0.8.1-6.redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-codehaus-jackson-1.9.13-10.redhat_00007.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-codehaus-jackson-core-asl-1.9.13-10.redhat_00007.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-codehaus-jackson-jaxrs-1.9.13-10.redhat_00007.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-codehaus-jackson-mapper-asl-1.9.13-10.redhat_00007.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-codehaus-jackson-xc-1.9.13-10.redhat_00007.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-codemodel-2.3.3-4.1.b02_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-commons-logging-jboss-logging-1.0.0-1.Final_redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-cryptacular-1.2.4-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-cxf-xjc-boolean-3.3.1-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-cxf-xjc-bug986-3.3.1-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-cxf-xjc-dv-3.3.1-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-cxf-xjc-runtime-3.3.1-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-cxf-xjc-ts-3.3.1-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-dom4j-2.1.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ecj-3.26.0-1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap7-jboss'},
      {'reference':'eap7-eclipse-jgit-5.13.0.202109080827-1.r_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-FastInfoset-1.2.13-11.1.redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-fge-btf-1.2.0-1.redhat_00007.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-fge-msg-simple-1.1.0-1.redhat_00007.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-concurrent-1.1.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-fastinfoset-1.2.13-11.1.redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-jaf-1.2.2-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-javamail-1.6.5-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-jaxb-2.3.3-4.1.b02_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-jsf-2.3.14-4.SP05_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-json-1.1.6-2.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-gnu-getopt-1.0.13-6.redhat_5.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-gson-2.8.9-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-guava-30.1.0-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-guava-failureaccess-1.0.1-1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-guava-libraries-30.1.0-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-h2database-1.4.197-2.redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hal-console-3.3.13-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-5.3.27-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-beanvalidation-api-2.0.2-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-commons-annotations-5.0.5-1.1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-core-5.3.27-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-envers-5.3.27-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-5.10.7-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-backend-jgroups-5.10.7-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-backend-jms-5.10.7-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-engine-5.10.7-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-orm-5.10.7-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-serialization-avro-5.10.7-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-validator-6.0.23-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-validator-cdi-6.0.23-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hornetq-2.4.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hornetq-commons-2.4.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hornetq-core-client-2.4.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hornetq-jms-client-2.4.8-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-httpcomponents-asyncclient-4.1.4-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-httpcomponents-client-4.5.13-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-httpcomponents-core-4.4.14-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-11.0.15-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-cachestore-jdbc-11.0.15-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-cachestore-remote-11.0.15-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-client-hotrod-11.0.15-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-commons-11.0.15-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-component-annotations-11.0.15-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-core-11.0.15-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-hibernate-cache-commons-11.0.15-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-hibernate-cache-spi-11.0.15-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-hibernate-cache-v53-11.0.15-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-1.5.3-2.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-api-1.5.3-2.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-impl-1.5.3-2.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-spi-1.5.3-2.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-core-api-1.5.3-2.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-core-impl-1.5.3-2.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-deployers-common-1.5.3-2.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-jdbc-1.5.3-2.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-validator-1.5.3-2.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-istack-commons-runtime-3.0.10-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-istack-commons-tools-3.0.10-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-annotations-2.12.6-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-core-2.12.6-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-coreutils-1.8.0-1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-databind-2.12.6.1-2.redhat_00004.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-datatype-jdk8-2.12.6-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-datatype-jsr310-2.12.6-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-jaxrs-base-2.12.6-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-jaxrs-json-provider-2.12.6-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-module-jaxb-annotations-2.12.6-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-modules-base-2.12.6-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-modules-java8-2.12.6-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jakarta-el-3.0.3-3.redhat_00007.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jakarta-security-enterprise-api-1.0.2-3.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jandex-2.4.2-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jansi-1.18.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jasypt-1.9.3-1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-java-classmate-1.5.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-javaee-jpa-spec-2.2.3-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-javaee-security-soteria-1.0.1-3.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-javaee-security-soteria-enterprise-1.0.1-3.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-javaewah-1.1.7-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-javapackages-tools-3.4.1-5.15.6.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-javassist-3.27.0-2.GA_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jaxb-jxc-2.3.3-4.1.b02_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jaxb-runtime-2.3.3-4.1.b02_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jaxb-xjc-2.3.3-4.1.b02_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jaxbintros-1.0.3-1.GA_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jaxen-1.1.6-14.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jberet-1.3.9-2.SP2_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jberet-core-1.3.9-2.SP2_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-aesh-2.4.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-annotations-api_1.3_spec-2.0.1-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-batch-api_1.0_spec-2.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-classfilewriter-1.2.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-common-beans-2.0.1-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-concurrency-api_1.0_spec-2.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-connector-api_1.7_spec-2.0.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-dmr-1.5.1-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-ejb-api_3.2_spec-2.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-ejb-client-4.0.44-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-ejb3-ext-api-2.3.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-el-api_3.0_spec-2.0.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-genericjms-2.0.9-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-iiop-client-1.0.1-3.Final_redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-interceptors-api_1.2_spec-2.0.0-3.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-invocation-1.6.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-j2eemgmt-api_1.1_spec-2.0.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jacc-api_1.5_spec-2.0.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jaspi-api_1.1_spec-2.0.1-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jaxb-api_2.3_spec-2.0.1-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jaxrpc-api_1.1_spec-2.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jaxrs-api_2.1_spec-2.0.1-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jaxws-api_2.3_spec-2.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jms-api_2.0_spec-2.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jsf-api_2.3_spec-3.0.0-5.SP06_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jsp-api_2.3_spec-2.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-logging-3.4.1-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-logmanager-2.1.18-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-marshalling-2.0.12-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-marshalling-river-2.0.12-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-metadata-13.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-metadata-appclient-13.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-metadata-common-13.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-metadata-ear-13.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-metadata-ejb-13.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-metadata-web-13.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-modules-1.12.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-msc-1.4.12-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-openjdk-orb-8.1.4-3.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-remoting-5.0.25-1.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-remoting-jmx-3.0.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-saaj-api_1.3_spec-1.0.6-1.Final_redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-saaj-api_1.4_spec-1.0.2-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-seam-int-7.0.0-6.GA_redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-security-negotiation-3.0.6-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-security-xacml-2.0.8-17.Final_redhat_8.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-1.10.0-18.Final_redhat_00017.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-cli-1.10.0-18.Final_redhat_00017.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-core-1.10.0-18.Final_redhat_00017.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-servlet-api_4.0_spec-2.0.0-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-stdio-1.1.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-threads-2.4.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-transaction-api_1.3_spec-2.0.0-4.Final_redhat_00005.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-transaction-spi-7.6.0-2.Final_redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-vfs-3.2.16-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-websocket-api_1.1_spec-2.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-weld-3.1-api-3.1.0-6.SP3_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-weld-3.1-api-weld-api-3.1.0-6.SP3_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-weld-3.1-api-weld-spi-3.1.0-6.SP3_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-xnio-base-3.8.7-1.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jbossws-api-1.1.2-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jbossws-common-3.3.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jbossws-common-tools-1.3.2-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jbossws-cxf-5.4.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jbossws-jaxws-undertow-httpspi-1.0.1-3.Final_redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jbossws-spi-3.3.1-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jcip-annotations-1.0.0-5.redhat_8.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jctools-2.1.2-1.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jctools-core-2.1.2-1.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jettison-1.4.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jgroups-4.2.15-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jgroups-azure-1.3.1-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jgroups-kubernetes-1.0.16-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-joda-time-2.9.7-2.redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-json-patch-1.9.0-1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jsonb-spec-1.0.2-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jsoup-1.14.2-1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jul-to-slf4j-stub-1.0.1-7.Final_redhat_3.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-log4j-2.17.1-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-log4j-jboss-logmanager-1.2.2-1.Final_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-log4j2-jboss-logmanager-1.0.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-lucene-analyzers-common-5.5.5-3.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-lucene-backward-codecs-5.5.5-3.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-lucene-core-5.5.5-3.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-lucene-facet-5.5.5-3.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-lucene-misc-5.5.5-3.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-lucene-queries-5.5.5-3.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-lucene-queryparser-5.5.5-3.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-lucene-solr-5.5.5-3.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-mod_cluster-1.4.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-mustache-java-0.9.6-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-mustache-java-compiler-0.9.6-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-5.11.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-compensations-5.11.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jbosstxbridge-5.11.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jbossxts-5.11.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jts-idlj-5.11.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jts-integration-5.11.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-api-5.11.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-bridge-5.11.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-integration-5.11.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-util-5.11.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-txframework-5.11.4-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-neethi-3.1.1-1.1.redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-buffer-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-dns-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-haproxy-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-http-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-http2-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-memcache-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-mqtt-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-redis-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-smtp-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-socks-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-stomp-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-xml-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-common-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-handler-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-handler-proxy-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-resolver-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-resolver-dns-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-resolver-dns-classes-macos-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-tcnative-2.0.52-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-classes-epoll-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-classes-kqueue-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-native-epoll-4.1.77-1.Final_redhat_00001.1.el9eap', 'cpu':'x86_64', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-native-unix-common-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-rxtx-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-sctp-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-udt-4.1.77-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-xnio-transport-0.1.9-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-objectweb-asm-9.1.0-1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-core-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-profile-api-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-saml-api-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-saml-impl-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-security-api-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-security-impl-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-soap-api-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-xacml-api-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-xacml-impl-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-xacml-saml-api-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-xacml-saml-impl-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-xmlsec-api-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-xmlsec-impl-3.3.1-1.1.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketbox-5.0.3-10.Final_redhat_00009.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketbox-commons-1.0.0-4.final_redhat_5.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketbox-infinispan-5.0.3-10.Final_redhat_00009.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-api-2.5.5-21.SP12_redhat_00011.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-bindings-2.5.5-26.SP12_redhat_00014.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-common-2.5.5-21.SP12_redhat_00011.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-config-2.5.5-21.SP12_redhat_00011.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-federation-2.5.5-21.SP12_redhat_00011.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-idm-api-2.5.5-21.SP12_redhat_00011.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-idm-impl-2.5.5-21.SP12_redhat_00011.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-idm-simple-schema-2.5.5-21.SP12_redhat_00011.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-impl-2.5.5-21.SP12_redhat_00011.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-wildfly8-2.5.5-26.SP12_redhat_00014.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-protostream-4.3.5-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-python3-javapackages-3.4.1-5.15.6.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-reactive-streams-1.0.3-2.redhat_00003.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-reactivex-rxjava-3.0.9-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-reactivex-rxjava2-2.2.20-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-relaxng-datatype-2.3.3-4.1.b02_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-atom-provider-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-cdi-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-client-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-crypto-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jackson-provider-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jackson2-provider-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jaxb-provider-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jaxrs-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jettison-provider-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jose-jwt-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jsapi-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-json-binding-provider-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-json-p-provider-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-multipart-provider-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-rxjava2-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-spring-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-validator-provider-11-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-yaml-provider-3.15.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-rngom-2.3.3-4.1.b02_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-runtime-1-18.el9eap', 'cpu':'x86_64', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-shibboleth-java-support-7.3.0-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-slf4j-1.7.22-4.1.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-slf4j-api-1.7.22-4.1.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-slf4j-ext-1.7.22-4.1.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-slf4j-jboss-logmanager-1.1.0-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-snakeyaml-1.29.0-1.redhat_00001.2.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-stax-ex-1.8.3-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-stax2-api-4.2.1-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-staxmapper-1.3.0-2.Final_redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-sun-istack-commons-3.0.10-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-sun-saaj-1.3-impl-1.3.16-18.SP1_redhat_6.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-sun-saaj-1.4-impl-1.4.1-1.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-sun-ws-metadata-2.0-api-1.0.0-7.MR1_redhat_8.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-taglibs-standard-compat-1.2.6-2.1.RC1_redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-taglibs-standard-impl-1.2.6-2.1.RC1_redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-taglibs-standard-spec-1.2.6-2.1.RC1_redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-txw2-2.3.3-4.1.b02_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-2.2.18-2.SP2_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-jastow-2.0.9-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-js-1.0.2-2.Final_redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-server-1.9.2-2.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-vdx-core-1.1.6-2.redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-vdx-wildfly-1.1.6-2.redhat_1.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-velocity-2.3.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-velocity-engine-core-2.3.0-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-cdi-2.0-api-2.0.2-2.redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-core-3.1.6-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-core-impl-3.1.6-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-core-jsf-3.1.6-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-ejb-3.1.6-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-jta-3.1.6-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-probe-core-3.1.6-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-web-3.1.6-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-7.4.6-5.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-client-config-1.0.1-2.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-common-1.5.4-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-discovery-client-1.2.1-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-1.15.13-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-tool-1.15.13-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-client-common-1.1.12-1.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-ejb-client-1.1.12-1.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-naming-client-1.1.12-1.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-transaction-client-1.1.12-1.SP1_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-javadocs-7.4.6-5.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-modules-7.4.6-5.GA_redhat_00002.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-naming-client-1.0.14-1.1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-openssl-2.2.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-openssl-el9-x86_64-2.2.2-1.Final_redhat_00002.1.el9eap', 'cpu':'x86_64', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-openssl-java-2.2.3-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-transaction-client-1.1.15-1.Final_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-woodstox-core-6.0.3-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ws-commons-XmlSchema-2.2.5-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wsdl4j-1.6.3-13.redhat_2.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-2.2.7-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-bindings-2.2.7-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-policy-2.2.7-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-ws-security-common-2.2.7-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-ws-security-dom-2.2.7-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-ws-security-policy-stax-2.2.7-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-ws-security-stax-2.2.7-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-xalan-j2-2.7.1-36.redhat_00013.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-xerces-j2-2.12.0-3.SP04_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-xml-commons-resolver-1.2.0-7.redhat_12.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-xml-resolver-1.2.0-7.redhat_12.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-xml-security-2.1.7-1.1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-xom-1.3.7-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-xsom-2.3.3-4.1.b02_redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-yasson-1.0.10-1.redhat_00001.1.el9eap', 'release':'9', 'el_string':'el9eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7 / eap7-FastInfoset / eap7-activemq-artemis / etc');
}
