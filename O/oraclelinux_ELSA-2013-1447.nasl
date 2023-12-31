#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1447 and 
# Oracle Linux Security Advisory ELSA-2013-1447 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70535);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-3829", "CVE-2013-4002", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5800", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5809", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5838", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851");
  script_bugtraq_id(61310, 63082, 63089, 63095, 63098, 63101, 63102, 63103, 63106, 63110, 63111, 63115, 63118, 63120, 63121, 63128, 63131, 63133, 63134, 63135, 63137, 63142, 63143, 63146, 63148, 63149, 63150, 63153, 63154);
  script_xref(name:"RHSA", value:"2013:1447");

  script_name(english:"Oracle Linux 5 : java-1.7.0-openjdk (ELSA-2013-1447)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:1447 :

Updated java-1.7.0-openjdk packages that fix various security issues
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 7 Java Runtime Environment and the
OpenJDK 7 Software Development Kit.

Multiple input checking flaws were found in the 2D component native
image parsing code. A specially crafted image file could trigger a
Java Virtual Machine memory corruption and, possibly, lead to
arbitrary code execution with the privileges of the user running the
Java Virtual Machine. (CVE-2013-5782)

The class loader did not properly check the package access for
non-public proxy classes. A remote attacker could possibly use this
flaw to execute arbitrary code with the privileges of the user running
the Java Virtual Machine. (CVE-2013-5830)

Multiple improper permission check issues were discovered in the 2D,
CORBA, JNDI, and Libraries components in OpenJDK. An untrusted Java
application or applet could use these flaws to bypass Java sandbox
restrictions. (CVE-2013-5829, CVE-2013-5814, CVE-2013-5817,
CVE-2013-5842, CVE-2013-5850, CVE-2013-5838)

Multiple input checking flaws were discovered in the JPEG image
reading and writing code in the 2D component. An untrusted Java
application or applet could use these flaws to corrupt the Java
Virtual Machine memory and bypass Java sandbox restrictions.
(CVE-2013-5809)

The FEATURE_SECURE_PROCESSING setting was not properly honored by the
javax.xml.transform package transformers. A remote attacker could use
this flaw to supply a crafted XML that would be processed without the
intended security restrictions. (CVE-2013-5802)

Multiple errors were discovered in the way the JAXP and Security
components processes XML inputs. A remote attacker could create a
crafted XML that would cause a Java application to use an excessive
amount of CPU and memory when processed. (CVE-2013-5825,
CVE-2013-4002, CVE-2013-5823)

Multiple improper permission check issues were discovered in the
Libraries, Swing, JAX-WS, JAXP, JGSS, AWT, Beans, and Scripting
components in OpenJDK. An untrusted Java application or applet could
use these flaws to bypass certain Java sandbox restrictions.
(CVE-2013-3829, CVE-2013-5840, CVE-2013-5774, CVE-2013-5783,
CVE-2013-5820, CVE-2013-5851, CVE-2013-5800, CVE-2013-5849,
CVE-2013-5790, CVE-2013-5784)

It was discovered that the 2D component image library did not properly
check bounds when performing image conversions. An untrusted Java
application or applet could use this flaw to disclose portions of the
Java Virtual Machine memory. (CVE-2013-5778)

Multiple input sanitization flaws were discovered in javadoc. When
javadoc documentation was generated from an untrusted Java source code
and hosted on a domain not controlled by the code author, these issues
could make it easier to perform cross-site scripting attacks.
(CVE-2013-5804, CVE-2013-5797)

Various OpenJDK classes that represent cryptographic keys could leak
private key information by including sensitive data in strings
returned by toString() methods. These flaws could possibly lead to an
unexpected exposure of sensitive key data. (CVE-2013-5780)

The Java Heap Analysis Tool (jhat) failed to properly escape all data
added into the HTML pages it generated. Crafted content in the memory
of a Java program analyzed using jhat could possibly be used to
conduct cross-site scripting attacks. (CVE-2013-5772)

The Kerberos implementation in OpenJDK did not properly parse KDC
responses. A malformed packet could cause a Java application using
JGSS to exit. (CVE-2013-5803)

All users of java-1.7.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-October/003751.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.7.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"java-1.7.0-openjdk-1.7.0.45-2.4.3.1.0.1.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.7.0-openjdk-demo-1.7.0.45-2.4.3.1.0.1.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.7.0-openjdk-devel-1.7.0.45-2.4.3.1.0.1.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.7.0-openjdk-javadoc-1.7.0.45-2.4.3.1.0.1.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.7.0-openjdk-src-1.7.0.45-2.4.3.1.0.1.el5_10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-demo / etc");
}
