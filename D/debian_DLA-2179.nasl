#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2179-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135722);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2020-10968", "CVE-2020-10969", "CVE-2020-11111", "CVE-2020-11112", "CVE-2020-11113", "CVE-2020-11619", "CVE-2020-11620");

  script_name(english:"Debian DLA-2179-1 : jackson-databind security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Following CVEs were reported against the jackson-databind source
package :

CVE-2020-10968

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related to
org.aoju.bus.proxy.provider.remoting.RmiProvider (aka bus-proxy).

CVE-2020-10969

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related to
javax.swing.JEditorPane.

CVE-2020-11111

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.activemq.* (aka activemq-jms, activemq-core, activemq-pool,
and activemq-pool-jms).

CVE-2020-11112

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.commons.proxy.provider.remoting.RmiProvider (aka
apache/commons-proxy).

CVE-2020-11113

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.openjpa.ee.WASRegistryManagedRuntime (aka openjpa).

CVE-2020-11619

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related to
org.springframework.aop.config.MethodLocatingFactoryBean (aka
spring-aop).

CVE-2020-11620

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.commons.jelly.impl.Embedded (aka commons-jelly).

For Debian 8 'Jessie', these problems have been fixed in version
2.4.2-2+deb8u14.

We recommend that you upgrade your jackson-databind packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/04/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/jackson-databind"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjackson2-databind-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjackson2-databind-java-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libjackson2-databind-java", reference:"2.4.2-2+deb8u14")) flag++;
if (deb_check(release:"8.0", prefix:"libjackson2-databind-java-doc", reference:"2.4.2-2+deb8u14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
