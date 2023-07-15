#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2424 and 
# Oracle Linux Security Advisory ELSA-2017-2424 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102346);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10081", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10135", "CVE-2017-10243");
  script_xref(name:"RHSA", value:"2017:2424");

  script_name(english:"Oracle Linux 6 / 7 : java-1.7.0-openjdk (ELSA-2017-2424)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:2424 :

An update for java-1.7.0-openjdk is now available for Red Hat
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-August/007115.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-August/007116.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.7.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"java-1.7.0-openjdk-1.7.0.151-2.6.11.0.0.1.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.7.0-openjdk-demo-1.7.0.151-2.6.11.0.0.1.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.7.0-openjdk-devel-1.7.0.151-2.6.11.0.0.1.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.151-2.6.11.0.0.1.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.7.0-openjdk-src-1.7.0.151-2.6.11.0.0.1.el6_9")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.151-2.6.11.1.0.1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.151-2.6.11.1.0.1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.151-2.6.11.1.0.1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.151-2.6.11.1.0.1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.151-2.6.11.1.0.1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-javadoc-1.7.0.151-2.6.11.1.0.1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.151-2.6.11.1.0.1.el7_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-accessibility / etc");
}
