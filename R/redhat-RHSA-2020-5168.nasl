##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:5168. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143213);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2020-27216");
  script_xref(name:"RHSA", value:"2020:5168");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"RHEL 7 : rh-eclipse (RHSA-2020:5168)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:5168 advisory.

  - jetty: local temporary directory hijacking vulnerability (CVE-2020-27216)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27216");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:5168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1891132");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27216");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(377);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-apache-bcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-apache-bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-apache-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-apache-oro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-apache-regexp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-apache-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-apache-xalan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-commons-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-commons-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-imageio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-jdepend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-jmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-jsch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-junit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-junit5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-swing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-testutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ant-xz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-antlr32-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-antlr32-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-antlr32-maven-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-antlr32-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-apache-sshd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-apache-sshd-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-apiguardian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-apiguardian-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-args4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-args4j-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-args4j-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-batik");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-batik-css");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-batik-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-batik-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-batik-rasterizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-batik-slideshow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-batik-squiggle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-batik-svgpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-batik-ttf2svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-batik-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-bouncycastle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-bouncycastle-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-bouncycastle-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-bouncycastle-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-bouncycastle-pkix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-bouncycastle-tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-cbi-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-cbi-plugins-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-decentxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-decentxml-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ecj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-contributor-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-ecf-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-ecf-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-ecf-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-egit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-emf-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-emf-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-emf-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-emf-xsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-equinox-osgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-gef");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-gef-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-jdt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-jgit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-license1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-license2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-m2e-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-m2e-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-m2e-workspace-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-mpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-p2-discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-pde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-platform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-pydev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-subclipse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-swt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-webtools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-webtools-servertools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-eclipse-webtools-sourceediting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ed25519-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-felix-gogo-command");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-felix-gogo-command-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-felix-gogo-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-felix-gogo-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-felix-gogo-runtime-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-felix-gogo-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-felix-gogo-shell-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-felix-scr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-felix-scr-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-javaewah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-javaewah-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-javaparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-javaparser-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jchardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jchardet-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jctools-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-continuation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-jaas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-servlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jetty-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jffi-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jffi-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jgit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jgit-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jna-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jna-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jnr-constants");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jnr-constants-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jnr-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jnr-ffi-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jnr-netdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jnr-netdb-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jnr-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jnr-posix-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jnr-x86asm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jnr-x86asm-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jsch-agent-proxy-connector-factory");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jsch-agent-proxy-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jsch-agent-proxy-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jsch-agent-proxy-jsch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jsch-agent-proxy-pageant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jsch-agent-proxy-sshagent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jsch-agent-proxy-trilead-ssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jsch-agent-proxy-usocket-jna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jsch-agent-proxy-usocket-nc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-junit5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-junit5-guide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-junit5-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jython-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jython-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jzlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jzlib-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-jzlib-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-analysis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-analyzers-smartcn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-backward-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-classification");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-grouping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-highlighter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-join");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-memory");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-monitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-queries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-queryparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-lucene-suggest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-maven-archetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-maven-archetype-catalog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-maven-archetype-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-maven-archetype-descriptor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-maven-archetype-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-maven-archetype-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-maven-archetype-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-maven-indexer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-maven-indexer-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-objectweb-asm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-objectweb-asm-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-opentest4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-opentest4j-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-os-maven-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-os-maven-plugin-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-sac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-sac-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-sat4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-scldevel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-sequence-library");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-sequence-library-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-sqljet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-sqljet-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-stringtemplate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-stringtemplate-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-svnkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-svnkit-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-svnkit-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-svnkit-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-takari-polyglot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-takari-polyglot-atom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-takari-polyglot-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-takari-polyglot-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-takari-polyglot-maven-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-takari-polyglot-translate-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-takari-polyglot-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-trilead-ssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-trilead-ssh2-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-tycho");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-tycho-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-univocity-parsers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-univocity-parsers-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ws-commons-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-ws-commons-util-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-xml-maven-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-xml-maven-plugin-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-xmlgraphics-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-xmlgraphics-commons-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-xmlrpc-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-xmlrpc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-xmlrpc-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eclipse-xmlrpc-server");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/devtools/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/devtools/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/devtools/1/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/devtools/1/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/devtools/1/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/devtools/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-eclipse-4.17-6.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-ant-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-antlr-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-apache-bcel-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-apache-bsf-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-apache-log4j-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-apache-oro-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-apache-regexp-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-apache-resolver-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-apache-xalan2-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-commons-logging-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-commons-net-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-imageio-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-javadoc-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-javamail-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-jdepend-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-jmf-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-jsch-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-junit-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-junit5-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-lib-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-manual-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-swing-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-testutil-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ant-xz-1.10.9-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-antlr32-java-3.2-28.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-antlr32-javadoc-3.2-28.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-antlr32-maven-plugin-3.2-28.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-antlr32-tool-3.2-28.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-apache-sshd-2.4.0-5.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-apache-sshd-javadoc-2.4.0-5.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-apiguardian-1.1.0-6.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-apiguardian-javadoc-1.1.0-6.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-args4j-2.33-12.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-args4j-javadoc-2.33-12.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-args4j-parent-2.33-12.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-batik-1.13-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-batik-css-1.13-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-batik-demo-1.13-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-batik-javadoc-1.13-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-batik-rasterizer-1.13-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-batik-slideshow-1.13-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-batik-squiggle-1.13-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-batik-svgpp-1.13-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-batik-ttf2svg-1.13-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-batik-util-1.13-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-bouncycastle-1.67-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-bouncycastle-javadoc-1.67-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-bouncycastle-mail-1.67-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-bouncycastle-pg-1.67-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-bouncycastle-pkix-1.67-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-bouncycastle-tls-1.67-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-cbi-plugins-1.1.7-8.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-cbi-plugins-javadoc-1.1.7-8.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-decentxml-1.4-24.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-decentxml-javadoc-1.4-24.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ecj-4.17-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-contributor-tools-4.17-2.2.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-ecf-core-3.14.17-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-ecf-runtime-3.14.17-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-ecf-sdk-3.14.17-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-egit-5.9.0-1.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-emf-core-2.23.0-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-emf-runtime-2.23.0-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-emf-sdk-2.23.0-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-emf-xsd-2.23.0-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-equinox-osgi-4.17-2.2.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-gef-3.11.0-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-gef-sdk-3.11.0-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-jdt-4.17-2.2.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-jgit-5.9.0-1.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-license1-1.0.1-12.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-license2-2.0.2-2.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-m2e-core-1.16.2-3.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-m2e-workspace-0.4.0-16.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-m2e-workspace-javadoc-0.4.0-16.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-mpc-1.8.4-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-p2-discovery-4.17-2.2.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-pde-4.17-2.2.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-platform-4.17-2.2.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-pydev-8.0.0-1.1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-subclipse-4.3.0-8.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-swt-4.17-2.2.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-eclipse-webtools-common-3.19.0-1.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-webtools-servertools-3.19.0-1.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-eclipse-webtools-sourceediting-3.19.0-1.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ed25519-java-0.3.0-8.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-felix-gogo-command-1.0.2-12.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-felix-gogo-command-javadoc-1.0.2-12.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-felix-gogo-parent-4-6.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-felix-gogo-runtime-1.1.0-8.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-felix-gogo-runtime-javadoc-1.1.0-8.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-felix-gogo-shell-1.1.0-6.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-felix-gogo-shell-javadoc-1.1.0-6.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-felix-scr-2.1.16-7.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-felix-scr-javadoc-2.1.16-7.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-javaewah-1.1.6-10.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-javaewah-javadoc-1.1.6-10.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-javaparser-3.14.16-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-javaparser-javadoc-3.14.16-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jchardet-1.1-23.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jchardet-javadoc-1.1-23.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jctools-3.1.0-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jctools-javadoc-3.1.0-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-client-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-continuation-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-http-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-io-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-jaas-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-javadoc-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-jmx-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-security-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-server-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-servlet-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-util-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-webapp-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jetty-xml-9.4.33-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jffi-1.2.23-2.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jffi-javadoc-1.2.23-2.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jffi-native-1.2.23-2.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jgit-5.9.0-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jgit-javadoc-5.9.0-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jna-5.4.0-7.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jna-contrib-5.4.0-7.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jna-javadoc-5.4.0-7.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jnr-constants-0.9.12-7.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jnr-constants-javadoc-0.9.12-7.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jnr-ffi-2.1.8-9.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jnr-ffi-javadoc-2.1.8-9.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jnr-netdb-1.1.6-11.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jnr-netdb-javadoc-1.1.6-11.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jnr-posix-3.0.47-7.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jnr-posix-javadoc-3.0.47-7.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jnr-x86asm-1.0.2-22.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jnr-x86asm-javadoc-1.0.2-22.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jsch-agent-proxy-connector-factory-0.0.8-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jsch-agent-proxy-core-0.0.8-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jsch-agent-proxy-javadoc-0.0.8-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jsch-agent-proxy-jsch-0.0.8-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jsch-agent-proxy-pageant-0.0.8-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jsch-agent-proxy-sshagent-0.0.8-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jsch-agent-proxy-trilead-ssh2-0.0.8-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jsch-agent-proxy-usocket-jna-0.0.8-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jsch-agent-proxy-usocket-nc-0.0.8-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-junit5-5.7.0-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-junit5-guide-5.7.0-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-junit5-javadoc-5.7.0-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jython-2.7.1-14.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jython-demo-2.7.1-14.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jython-javadoc-2.7.1-14.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jzlib-1.1.3-15.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jzlib-demo-1.1.3-15.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-jzlib-javadoc-1.1.3-15.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-analysis-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-analyzers-smartcn-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-backward-codecs-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-classification-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-codecs-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-grouping-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-highlighter-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-javadoc-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-join-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-memory-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-misc-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-monitor-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-queries-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-queryparser-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-sandbox-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-lucene-suggest-8.6.3-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-maven-archetype-3.2.0-1.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-maven-archetype-catalog-3.2.0-1.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-maven-archetype-common-3.2.0-1.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-maven-archetype-descriptor-3.2.0-1.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-maven-archetype-javadoc-3.2.0-1.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-maven-archetype-packaging-3.2.0-1.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-maven-archetype-plugin-3.2.0-1.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-maven-indexer-6.0.0-5.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-maven-indexer-javadoc-6.0.0-5.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-netty-4.1.51-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-objectweb-asm-8.0.1-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-objectweb-asm-javadoc-8.0.1-1.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-opentest4j-1.2.0-4.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-opentest4j-javadoc-1.2.0-4.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-os-maven-plugin-1.6.2-2.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-os-maven-plugin-javadoc-1.6.2-2.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-runtime-4.17-6.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-sac-1.3-34.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-sac-javadoc-1.3-34.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-sat4j-2.3.5-20.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-scldevel-4.17-6.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-sequence-library-1.0.3-8.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-sequence-library-javadoc-1.0.3-8.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-sqljet-1.1.10-18.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-sqljet-javadoc-1.1.10-18.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-stringtemplate-3.2.1-24.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-stringtemplate-javadoc-3.2.1-24.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-svnkit-1.8.12-9.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-svnkit-cli-1.8.12-9.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-svnkit-javadoc-1.8.12-9.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-svnkit-javahl-1.8.12-9.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-takari-polyglot-0.4.5-2.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-takari-polyglot-atom-0.4.5-2.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-takari-polyglot-common-0.4.5-2.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-takari-polyglot-javadoc-0.4.5-2.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-takari-polyglot-maven-plugin-0.4.5-2.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-takari-polyglot-translate-plugin-0.4.5-2.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-takari-polyglot-xml-0.4.5-2.1.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-trilead-ssh2-217.21-3.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-trilead-ssh2-javadoc-217.21-3.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-tycho-1.7.0-2.5.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-tycho-javadoc-1.7.0-2.5.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-univocity-parsers-2.9.0-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-univocity-parsers-javadoc-2.9.0-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ws-commons-util-1.0.2-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-ws-commons-util-javadoc-1.0.2-14.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-xml-maven-plugin-1.0.2-7.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-xml-maven-plugin-javadoc-1.0.2-7.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-xmlgraphics-commons-2.4-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-xmlgraphics-commons-javadoc-2.4-1.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-eclipse-xmlrpc-client-3.1.3-27.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-xmlrpc-common-3.1.3-27.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-xmlrpc-javadoc-3.1.3-27.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-eclipse-xmlrpc-server-3.1.3-27.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-eclipse / rh-eclipse-ant / rh-eclipse-ant-antlr / etc');
}
