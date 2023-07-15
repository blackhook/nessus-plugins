#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-869.
#

include("compat.inc");

if (description)
{
  script_id(102502);
  script_version("3.6");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10081", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10135", "CVE-2017-10243");
  script_xref(name:"ALAS", value:"2017-869");

  script_name(english:"Amazon Linux AMI : java-1.7.0-openjdk (ALAS-2017-869)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the DCG implementation in the RMI component of
OpenJDK failed to correctly handle references. A remote attacker could
possibly use this flaw to execute arbitrary code with the privileges
of RMI registry or a Java RMI application. (CVE-2017-10102)

Multiple flaws were discovered in the RMI, JAXP, ImageIO, Libraries,
AWT, Hotspot, and Security components in OpenJDK. An untrusted Java
application or applet could use these flaws to completely bypass Java
sandbox restrictions. (CVE-2017-10107 , CVE-2017-10096 ,
CVE-2017-10101 , CVE-2017-10089 , CVE-2017-10090 , CVE-2017-10087 ,
CVE-2017-10110 , CVE-2017-10074 , CVE-2017-10067)

It was discovered that the LDAPCertStore class in the Security
component of OpenJDK followed LDAP referrals to arbitrary URLs. A
specially crafted LDAP referral URL could cause LDAPCertStore to
communicate with non-LDAP servers. (CVE-2017-10116)

It was discovered that the wsdlimport tool in the JAX-WS component of
OpenJDK did not use secure XML parser settings when parsing WSDL XML
documents. A specially crafted WSDL document could cause wsdlimport to
use an excessive amount of CPU and memory, open connections to other
hosts, or leak information. (CVE-2017-10243)

A covert timing channel flaw was found in the DSA implementation in
the JCE component of OpenJDK. A remote attacker able to make a Java
application generate DSA signatures on demand could possibly use this
flaw to extract certain information about the used key via a timing
side channel. (CVE-2017-10115)

A covert timing channel flaw was found in the PKCS#8 implementation in
the JCE component of OpenJDK. A remote attacker able to make a Java
application repeatedly compare PKCS#8 key against an attacker
controlled value could possibly use this flaw to determine the key via
a timing side channel. (CVE-2017-10135)

It was discovered that the BasicAttribute and CodeSource classes in
OpenJDK did not limit the amount of memory allocated when creating
object instances from a serialized form. A specially crafted
serialized input stream could cause Java to consume an excessive
amount of memory. (CVE-2017-10108 , CVE-2017-10109)

A flaw was found in the Hotspot component in OpenJDK. An untrusted
Java application or applet could use this flaw to bypass certain Java
sandbox restrictions. (CVE-2017-10081)

It was discovered that the JPEGImageReader implementation in the 2D
component of OpenJDK would, in certain cases, read all image data even
if it was not used later. A specially crafted image could cause a Java
application to temporarily use an excessive amount of CPU and memory.
(CVE-2017-10053)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-869.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.7.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-1.7.0.151-2.6.11.0.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.151-2.6.11.0.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-demo-1.7.0.151-2.6.11.0.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-devel-1.7.0.151-2.6.11.0.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-javadoc-1.7.0.151-2.6.11.0.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-src-1.7.0.151-2.6.11.0.74.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-debuginfo / etc");
}
