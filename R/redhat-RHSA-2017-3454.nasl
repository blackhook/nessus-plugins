#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3454. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105268);
  script_version("3.11");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2016-4978", "CVE-2016-4993", "CVE-2016-5406", "CVE-2016-6311", "CVE-2016-7046", "CVE-2016-7061", "CVE-2016-8627", "CVE-2016-8656", "CVE-2016-9589", "CVE-2017-12165", "CVE-2017-12167", "CVE-2017-2595", "CVE-2017-2666", "CVE-2017-2670", "CVE-2017-7525", "CVE-2017-7536", "CVE-2017-7559");
  script_xref(name:"RHSA", value:"2017:3454");

  script_name(english:"RHEL 6 : JBoss EAP (RHSA-2017:3454)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat JBoss Enterprise Application
Platform 7.1 for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform is a platform for Java
applications based on the JBoss Application Server.

This release of Red Hat JBoss Enterprise Application Platform 7.1.0
serves as a replacement for Red Hat JBoss Enterprise Application
Platform 7.0.0, and includes bug fixes and enhancements, which are
documented in the Release Notes document linked to in the References.

Security Fix(es) :

* A Denial of Service can be caused when a long request is sent to EAP
7. (CVE-2016-7046)

* The jboss init script unsafe file handling resulting in local
privilege escalation. (CVE-2016-8656)

* A deserialization vulnerability via readValue method of ObjectMapper
which allows arbitrary code execution. (CVE-2017-7525)

* JMSObjectMessage deserializes potentially malicious objects allowing
Remote Code Execution. (CVE-2016-4978)

* Undertow is vulnerable to the injection of arbitrary HTTP headers,
and also response splitting. (CVE-2016-4993)

* The domain controller will not propagate its administrative RBAC
configuration to some slaves leading to escalate their privileges.
(CVE-2016-5406)

* Internal IP address disclosed on redirect when request header Host
field is not set. (CVE-2016-6311)

* Potential EAP resource starvation DOS attack via GET requests for
server log files. (CVE-2016-8627)

* Inefficient Header Cache could cause denial of service.
(CVE-2016-9589)

* The log file viewer allows arbitrary file read to authenticated user
via path traversal. (CVE-2017-2595)

* HTTP Request smuggling vulnerability due to permitting invalid
characters in HTTP requests. (CVE-2017-2666)

* Websocket non clean close can cause IO thread to get stuck in a
loop. (CVE-2017-2670)

* Privilege escalation with security manager's reflective permissions
when granted to Hibernate Validator. (CVE-2017-7536)

* Potential http request smuggling as Undertow parses the http headers
with unusual whitespaces. (CVE-2017-7559)

* Properties based files of the management and the application realm
are world readable allowing access to users and roles information to
all the users logged in to the system. (CVE-2017-12167)

* RBAC configuration allows users with a Monitor role to view the
sensitive information. (CVE-2016-7061)

* Improper whitespace parsing leading to potential HTTP request
smuggling. (CVE-2017-12165)

Red Hat would like to thank Liao Xinxi (NSFOCUS) for reporting
CVE-2017-7525; Calum Hutton (NCC Group) and Mikhail Egorov (Odin) for
reporting CVE-2016-4993; Luca Bueti for reporting CVE-2016-6311;
Gabriel Lavoie (Halogen Software) for reporting CVE-2016-9589; and
Gregory Ramsperger and Ryan Moak for reporting CVE-2017-2670. The
CVE-2016-5406 issue was discovered by Tomaz Cerar (Red Hat); the
CVE-2016-8627 issue was discovered by Darran Lofthouse (Red Hat) and
Brian Stansberry (Red Hat); the CVE-2017-2666 issue was discovered by
Radim Hatlapatka (Red Hat); the CVE-2017-7536 issue was discovered by
Gunnar Morling (Red Hat); the CVE-2017-7559 and CVE-2017-12165 issues
were discovered by Stuart Douglas (Red Hat); and the CVE-2017-12167
issue was discovered by Brian Stansberry (Red Hat) and Jeremy Choi
(Red Hat). Upstream acknowledges WildFly as the original reporter of
CVE-2016-6311."
  );
  # https://access.redhat.com/documentation/en/
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:3454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12167"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-xjc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-mime4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-native-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-artemis-wildfly-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-azure-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-pkix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-core-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-mapper-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-xc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-commons-logging-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cryptacular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-boolean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-bug986");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cxf-xjc-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ecj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-concurrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-el-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jaf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-guava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-guava-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-h2database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-jpa-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-backend-jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-backend-jms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-orm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-serialization-avro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-validator-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-httpcomponents-asyncclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-httpcomponents-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-deployers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jsr310");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-modules-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jandex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-java-classmate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxb-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxb-jxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxb-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxb-xjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxbintros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-aesh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-annotations-api_1.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-classfilewriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-concurrency-api_1.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-connector-api_1.7_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-dmr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ejb-api_3.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ejb3-ext-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-el-api_3.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-genericjms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-iiop-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-interceptors-api_1.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-invocation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jacc-api_1.5_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jaspi-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jaxb-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jaxrpc-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jaxrs-api_2.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jaxws-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jms-api_2.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jsf-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jsp-api_2.3_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-marshalling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-marshalling-river");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-ear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-openjdk-orb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-remoting-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-saaj-api_1.3_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-seam-int");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-security-xacml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4-to-eap7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4-to-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.0-to-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.0-to-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.1-to-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2-to-eap7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2-to-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0-to-eap7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0-to-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-servlet-api_3.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-transaction-api_1.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-transaction-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-vfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-websocket-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-weld-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-jaxws-undertow-httpspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jcl-over-slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jettison");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jgroups-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-joda-time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jul-to-slf4j-stub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-mustache-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-mustache-java-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-compensations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jbosstxbridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jbossxts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-idlj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-txframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-neethi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-xnio-transport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-objectweb-asm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox-infinispan");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-p-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-multipart-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-spring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-validator-provider-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-yaml-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-rngom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-shibboleth-java-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-slf4j-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-slf4j-ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-snakeyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-staxmapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-sun-saaj-1.3-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-sun-ws-metadata-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-taglibs-standard-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-taglibs-standard-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-taglibs-standard-spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-jastow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-vdx-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-vdx-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-probe-core");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-web-console-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-woodstox-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-policy-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xml-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xom");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:3454";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;

  if (! (rpm_exists(release:"RHEL6", rpm:"jbossas-welcome-content-eap"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-cli-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-commons-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-core-client-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-dto-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-hornetq-protocol-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-hqclient-protocol-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-jdbc-store-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-jms-client-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-jms-server-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-journal-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-native-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-ra-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-selector-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-server-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-activemq-artemis-service-extensions-1.5.5.008-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-antlr-2.7.7-35.redhat_7.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-commons-beanutils-1.9.3-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-commons-cli-1.3.1-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-commons-io-2.5.0-2.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-3.1.12-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-rt-3.1.12-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-services-3.1.12-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-tools-3.1.12-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-cxf-xjc-utils-3.0.5-3.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-apache-mime4j-0.6.0-2.redhat_6.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eap7-artemis-native-1.5.0-5.redhat_1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eap7-artemis-native-1.5.0-5.redhat_1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eap7-artemis-native-wildfly-1.5.0-5.redhat_1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eap7-artemis-native-wildfly-1.5.0-5.redhat_1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-artemis-wildfly-integration-1.0.2-3.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-azure-storage-5.0.0-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-bouncycastle-1.56.0-4.redhat_2.2.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-bouncycastle-mail-1.56.0-4.redhat_2.2.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-bouncycastle-pkix-1.56.0-4.redhat_2.2.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-bouncycastle-prov-1.56.0-4.redhat_2.2.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-codehaus-jackson-1.9.13-7.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-codehaus-jackson-core-asl-1.9.13-7.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-codehaus-jackson-jaxrs-1.9.13-7.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-codehaus-jackson-mapper-asl-1.9.13-7.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-codehaus-jackson-xc-1.9.13-7.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-codemodel-2.2.11-10.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-commons-logging-jboss-logmanager-1.0.2-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-cryptacular-1.2.0-3.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-cxf-xjc-boolean-3.0.5-3.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-cxf-xjc-bug986-3.0.5-3.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-cxf-xjc-dv-3.0.5-3.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-cxf-xjc-runtime-3.0.5-3.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-cxf-xjc-ts-3.0.5-3.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ecj-4.6.1-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-glassfish-concurrent-1.0.0-3.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-glassfish-el-3.0.1-2.b08_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-glassfish-el-impl-3.0.1-2.b08_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-glassfish-jaf-1.1.1-21.redhat_5.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-glassfish-javamail-1.5.6-4.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-glassfish-jaxb-2.2.11-10.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-glassfish-jsf-2.2.13-5.SP4_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-glassfish-json-1.0.4-4.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-guava-20.0.0-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-guava-libraries-20.0.0-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-h2database-1.4.193-4.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-5.1.10-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-commons-annotations-5.0.1-3.Final_redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-core-5.1.10-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-entitymanager-5.1.10-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-envers-5.1.10-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-infinispan-5.1.10-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-java8-5.1.10-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-jpa-2.1-api-1.0.0-3.Final_redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-search-5.5.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-search-backend-jgroups-5.5.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-search-backend-jms-5.5.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-search-engine-5.5.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-search-orm-5.5.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-search-serialization-avro-5.5.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-validator-5.3.5-3.Final_redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-hibernate-validator-cdi-5.3.5-3.Final_redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-httpcomponents-asyncclient-4.1.2-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-httpcomponents-client-4.5.2-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-httpcomponents-core-4.4.4-2.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-8.2.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-cachestore-jdbc-8.2.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-cachestore-remote-8.2.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-client-hotrod-8.2.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-commons-8.2.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-infinispan-core-8.2.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-1.4.6-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-common-api-1.4.6-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-common-impl-1.4.6-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-common-spi-1.4.6-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-core-api-1.4.6-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-core-impl-1.4.6-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-deployers-common-1.4.6-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-jdbc-1.4.6-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-ironjacamar-validator-1.4.6-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-annotations-2.8.9-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-core-2.8.9-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-databind-2.8.9-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-datatype-jdk8-2.8.9-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-datatype-jsr310-2.8.9-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-jaxrs-base-2.8.9-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-jaxrs-json-provider-2.8.9-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-module-jaxb-annotations-2.8.9-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jackson-modules-java8-2.8.9-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jandex-2.0.3-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jansi-1.16.0-5.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-java-classmate-1.3.3-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-javassist-3.20.0-2.GA_redhat_3.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jaxb-core-2.2.11-10.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jaxb-jxc-2.2.11-10.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jaxb-runtime-2.2.11-10.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jaxb-xjc-2.2.11-10.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jaxbintros-1.0.2-19.GA_redhat_8.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jaxen-1.1.6-3.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jberet-1.2.4-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jberet-core-1.2.4-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-aesh-0.66.19-2.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-annotations-api_1.2_spec-1.0.0-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-classfilewriter-1.2.1-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-concurrency-api_1.0_spec-1.0.0-4.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-connector-api_1.7_spec-1.0.0-5.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-dmr-1.4.1-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-ejb-api_3.2_spec-1.0.0-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-ejb-client-4.0.9-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-ejb3-ext-api-2.2.0-4.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-el-api_3.0_spec-1.0.9-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-genericjms-2.0.0-4.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-iiop-client-1.0.1-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-interceptors-api_1.2_spec-1.0.0-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-invocation-1.5.0-5.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-jacc-api_1.5_spec-1.0.1-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-jaspi-api_1.1_spec-1.0.0-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-jaxb-api_2.2_spec-1.0.4-6.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-jaxrpc-api_1.1_spec-1.0.1-8.Final_redhat_5.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-jaxrs-api_2.0_spec-1.0.0-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-jaxws-api_2.2_spec-2.0.4-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-jms-api_2.0_spec-1.0.1-4.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-jsf-api_2.2_spec-2.2.13-4.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-jsp-api_2.3_spec-1.0.1-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-logmanager-2.0.7-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-marshalling-2.0.2-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-marshalling-river-2.0.2-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-metadata-10.0.2-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-metadata-appclient-10.0.2-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-metadata-common-10.0.2-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-metadata-ear-10.0.2-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-metadata-ejb-10.0.2-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-metadata-web-10.0.2-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-modules-1.6.0-11.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-openjdk-orb-8.0.8-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-remoting-5.0.5-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-remoting-jmx-3.0.0-8.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-saaj-api_1.3_spec-1.0.4-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-seam-int-7.0.0-5.GA_redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-security-xacml-2.0.8-16.Final_redhat_8.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-cli-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-core-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap6.4-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap6.4-to-eap7.0-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap6.4-to-eap7.1-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap7.0-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap7.0-to-eap7.1-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-eap7.1-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly10.0-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly10.0-to-eap7.1-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly10.1-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly10.1-to-eap7.1-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly8.2-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly8.2-to-eap7.0-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly8.2-to-eap7.1-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly9.0-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly9.0-to-eap7.0-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-server-migration-wildfly9.0-to-eap7.1-1.0.3-4.Final_redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-servlet-api_3.1_spec-1.0.0-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-transaction-api_1.2_spec-1.0.1-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-transaction-spi-7.6.0-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-vfs-3.2.12-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-websocket-api_1.1_spec-1.1.1-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-weld-2.2-api-2.4.0-2.SP1_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-xnio-base-3.5.4-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jbossws-common-tools-1.2.4-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jbossws-cxf-5.1.9-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jbossws-jaxws-undertow-httpspi-1.0.1-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jbossws-spi-3.1.4-3.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jcl-over-slf4j-1.7.22-2.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jettison-1.3.8-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jgroups-3.6.13-2.Final_redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jgroups-azure-1.1.0-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-joda-time-2.9.7-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jsoup-1.8.3-3.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jul-to-slf4j-stub-1.0.1-6.Final_redhat_3.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-mod_cluster-1.3.7-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-mustache-java-0.9.4-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-mustache-java-compiler-0.9.4-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-5.5.30-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-compensations-5.5.30-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-jbosstxbridge-5.5.30-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-jbossxts-5.5.30-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-jts-idlj-5.5.30-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-jts-integration-5.5.30-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-restat-api-5.5.30-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-restat-bridge-5.5.30-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-restat-integration-5.5.30-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-restat-util-5.5.30-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-narayana-txframework-5.5.30-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-neethi-3.0.3-3.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-netty-4.1.9-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-netty-all-4.1.9-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-netty-xnio-transport-0.1.2-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-objectweb-asm-3.3.1-14.redhat_13.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketbox-5.0.2-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketbox-commons-1.0.0-3.final_redhat_5.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-picketbox-infinispan-5.0.2-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-atom-provider-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-cdi-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-client-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-crypto-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jackson-provider-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jackson2-provider-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jaxb-provider-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jaxrs-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jettison-provider-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jose-jwt-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-jsapi-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-json-p-provider-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-multipart-provider-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-spring-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-validator-provider-11-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-resteasy-yaml-provider-3.0.24-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-rngom-2.2.11-10.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-shibboleth-java-support-7.1.1-3.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-slf4j-1.7.22-2.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-slf4j-api-1.7.22-2.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-slf4j-ext-1.7.22-2.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-snakeyaml-1.17.0-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-staxmapper-1.3.0-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-sun-saaj-1.3-impl-1.3.16-16.SP1_redhat_6.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-sun-ws-metadata-2.0-api-1.0.0-6.MR1_redhat_8.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-taglibs-standard-compat-1.2.6-1.RC1_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-taglibs-standard-impl-1.2.6-1.RC1_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-taglibs-standard-spec-1.2.6-1.RC1_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-txw2-2.2.11-10.redhat_4.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-undertow-1.4.18-2.Final_redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-undertow-jastow-2.0.2-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-undertow-server-1.0.1-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-vdx-core-1.1.6-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-vdx-wildfly-1.1.6-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-weld-core-2.4.3-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-weld-core-impl-2.4.3-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-weld-core-jsf-2.4.3-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-weld-probe-core-2.4.3-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-7.1.0-64.GA_redhat_11.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-client-config-1.0.0-7.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-common-1.2.0-10.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-discovery-client-1.0.0-9.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-elytron-1.1.7-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-elytron-tool-1.0.5-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-http-client-common-1.0.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-http-ejb-client-1.0.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-http-naming-client-1.0.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-http-transaction-client-1.0.8-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-javadocs-7.1.0-27.GA_redhat_11.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-modules-7.1.0-64.GA_redhat_11.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-naming-client-1.0.7-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-openssl-1.0.2-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-openssl-java-1.0.2-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eap7-wildfly-openssl-linux-1.0.2-13.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eap7-wildfly-openssl-linux-1.0.2-13.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eap7-wildfly-openssl-linux-debuginfo-1.0.2-13.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eap7-wildfly-openssl-linux-debuginfo-1.0.2-13.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-transaction-client-1.0.2-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wildfly-web-console-eap-2.9.15-2.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-woodstox-core-5.0.3-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-2.1.10-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-bindings-2.1.10-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-policy-2.1.10-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-ws-security-common-2.1.10-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-ws-security-dom-2.1.10-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-ws-security-policy-stax-2.1.10-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-wss4j-ws-security-stax-2.1.10-1.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-xml-security-2.0.8-2.redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-xom-1.2.10-2.redhat_1.1.ep7.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eap7-activemq-artemis / eap7-activemq-artemis-cli / etc");
  }
}
