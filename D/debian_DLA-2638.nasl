#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2638-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(149019);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-24616", "CVE-2020-24750", "CVE-2020-35490", "CVE-2020-35491", "CVE-2020-35728", "CVE-2020-36179", "CVE-2020-36180", "CVE-2020-36181", "CVE-2020-36182", "CVE-2020-36183", "CVE-2020-36184", "CVE-2020-36185", "CVE-2020-36186", "CVE-2020-36187", "CVE-2020-36188", "CVE-2020-36189", "CVE-2021-20190");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DLA-2638-1 : jackson-databind security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security vulnerabilities were found in Jackson Databind.

CVE-2020-24616

FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the
interaction between serialization gadgets and typing, related to
br.com.anteros.dbcp.AnterosDBCPDataSource (aka Anteros-DBCP).

CVE-2020-24750

FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the
interaction between serialization gadgets and typing, related to
com.pastdev.httpcomponents.configuration.JndiConfiguration.

CVE-2020-25649

A flaw was found in FasterXML Jackson Databind, where it did not have
entity expansion secured properly. This flaw allows vulnerability to
XML external entity (XXE) attacks. The highest threat from this
vulnerability is data integrity.

CVE-2020-35490

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.commons.dbcp2.datasources.PerUserPoolDataSource.

CVE-2020-35491

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.commons.dbcp2.datasources.SharedPoolDataSource.

CVE-2020-35728

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
com.oracle.wls.shaded.org.apache.xalan.lib.sql.JNDIConnectionPool (aka
embedded Xalan in org.glassfish.web/javax.servlet.jsp.jstl).

CVE-2020-36179

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
oadd.org.apache.commons.dbcp.cpdsadapter.DriverAdapterCPDS.

CVE-2020-36180

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS.

CVE-2020-36181

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.tomcat.dbcp.dbcp.cpdsadapter.DriverAdapterCPDS.

CVE-2020-36182

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.tomcat.dbcp.dbcp2.cpdsadapter.DriverAdapterCPDS.

CVE-2020-36183

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
org.docx4j.org.apache.xalan.lib.sql.JNDIConnectionPool.

CVE-2020-36184

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.tomcat.dbcp.dbcp2.datasources.PerUserPoolDataSource.

CVE-2020-36185

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.tomcat.dbcp.dbcp2.datasources.SharedPoolDataSource.

CVE-2020-36186

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.tomcat.dbcp.dbcp.datasources.PerUserPoolDataSource.

CVE-2020-36187

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.tomcat.dbcp.dbcp.datasources.SharedPoolDataSource.

CVE-2020-36188

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
com.newrelic.agent.deps.ch.qos.logback.core.db.JNDICS.

CVE-2020-36189

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
com.newrelic.agent.deps.ch.qos.logback.core.db.DMCS.

CVE-2021-20190

A flaw was found in jackson-databind before 2.9.10.7. FasterXML
mishandles the interaction between serialization gadgets and typing.
The highest threat from this vulnerability is to data confidentiality
and integrity as well as system availability.

For Debian 9 stretch, these problems have been fixed in version
2.8.6-1+deb9u9.

We recommend that you upgrade your jackson-databind packages.

For the detailed security status of jackson-databind please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/jackson-databind

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/jackson-databind"
  );
  # https://security-tracker.debian.org/tracker/source-package/jackson-databind
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61134ddf"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjackson2-databind-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjackson2-databind-java-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"9.0", prefix:"libjackson2-databind-java", reference:"2.8.6-1+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"libjackson2-databind-java-doc", reference:"2.8.6-1+deb9u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
