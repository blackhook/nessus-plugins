#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2424 and 
# CentOS Errata and Security Advisory 2017:2424 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102503);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10081", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10135", "CVE-2017-10243");
  script_xref(name:"RHSA", value:"2017:2424");

  script_name(english:"CentOS 6 / 7 : java-1.7.0-openjdk (CESA-2017:2424)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.7.0-openjdk is now available for Red Hat
Enterprise Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

Security Fix(es) :

* It was discovered that the DCG implementation in the RMI component
of OpenJDK failed to correctly handle references. A remote attacker
could possibly use this flaw to execute arbitrary code with the
privileges of RMI registry or a Java RMI application. (CVE-2017-10102)

* Multiple flaws were discovered in the RMI, JAXP, ImageIO, Libraries,
AWT, Hotspot, and Security components in OpenJDK. An untrusted Java
application or applet could use these flaws to completely bypass Java
sandbox restrictions. (CVE-2017-10107, CVE-2017-10096, CVE-2017-10101,
CVE-2017-10089, CVE-2017-10090, CVE-2017-10087, CVE-2017-10110,
CVE-2017-10074, CVE-2017-10067)

* It was discovered that the LDAPCertStore class in the Security
component of OpenJDK followed LDAP referrals to arbitrary URLs. A
specially crafted LDAP referral URL could cause LDAPCertStore to
communicate with non-LDAP servers. (CVE-2017-10116)

* It was discovered that the wsdlimport tool in the JAX-WS component
of OpenJDK did not use secure XML parser settings when parsing WSDL
XML documents. A specially crafted WSDL document could cause
wsdlimport to use an excessive amount of CPU and memory, open
connections to other hosts, or leak information. (CVE-2017-10243)

* A covert timing channel flaw was found in the DSA implementation in
the JCE component of OpenJDK. A remote attacker able to make a Java
application generate DSA signatures on demand could possibly use this
flaw to extract certain information about the used key via a timing
side channel. (CVE-2017-10115)

* A covert timing channel flaw was found in the PKCS#8 implementation
in the JCE component of OpenJDK. A remote attacker able to make a Java
application repeatedly compare PKCS#8 key against an attacker
controlled value could possibly use this flaw to determine the key via
a timing side channel. (CVE-2017-10135)

* It was discovered that the BasicAttribute and CodeSource classes in
OpenJDK did not limit the amount of memory allocated when creating
object instances from a serialized form. A specially crafted
serialized input stream could cause Java to consume an excessive
amount of memory. (CVE-2017-10108, CVE-2017-10109)

* A flaw was found in the Hotspot component in OpenJDK. An untrusted
Java application or applet could use this flaw to bypass certain Java
sandbox restrictions. (CVE-2017-10081)

* It was discovered that the JPEGImageReader implementation in the 2D
component of OpenJDK would, in certain cases, read all image data even
if it was not used later. A specially crafted image could cause a Java
application to temporarily use an excessive amount of CPU and memory.
(CVE-2017-10053)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-August/022517.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17a3bcf1"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004673.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?643b4024"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.7.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10087");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-1.7.0.151-2.6.11.0.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-demo-1.7.0.151-2.6.11.0.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-devel-1.7.0.151-2.6.11.0.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.151-2.6.11.0.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-src-1.7.0.151-2.6.11.0.el6_9")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.151-2.6.11.1.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.151-2.6.11.1.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.151-2.6.11.1.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.151-2.6.11.1.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.151-2.6.11.1.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-javadoc-1.7.0.151-2.6.11.1.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.151-2.6.11.1.el7_4")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-accessibility / etc");
}
