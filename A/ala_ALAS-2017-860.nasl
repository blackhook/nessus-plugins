#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-860.
#

include("compat.inc");

if (description)
{
  script_id(101958);
  script_version("3.8");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10135", "CVE-2017-10193", "CVE-2017-10198");
  script_xref(name:"ALAS", value:"2017-860");

  script_name(english:"Amazon Linux AMI : java-1.8.0-openjdk (ALAS-2017-860)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Incorrect enforcement of certificate path restrictions :

It was discovered that the Security component of OpenJDK could fail to
properly enforce restrictions defined for processing of X.509
certificate chains. A remote attacker could possibly use this flaw to
make Java accept certificate using one of the disabled algorithms.
(CVE-2017-10198)

Insufficient access control checks in XML transformations
(CVE-2017-10096)

Incorrect range checks in LambdaFormEditor (CVE-2017-10111)

Insufficient access control checks in AsynchronousChannelGroupImpl
(CVE-2017-10090)

Incorrect key size constraint check (CVE-2017-10193)

Integer overflows in range check loop predicates (CVE-2017-10074)

PKCS#8 implementation timing attack :

A covert timing channel flaw was found in the PKCS#8 implementation in
the JCE component of OpenJDK. A remote attacker able to make a Java
application repeatedly compare PKCS#8 key against an attacker
controlled value could possibly use this flaw to determine the key via
a timing side channel. (CVE-2017-10135)

Incorrect handling of references in DGC :

It was discovered that the DCG implementation in the RMI component of
OpenJDK failed to correctly handle references. A remote attacker could
possibly use this flaw to execute arbitrary code with the privileges
of RMI registry or a Java RMI application. (CVE-2017-10102)

Insufficient access control checks in ImageWatched (CVE-2017-10110)

Unrestricted access to com.sun.org.apache.xml.internal.resolver
(CVE-2017-10101)

DSA implementation timing attack :

A covert timing channel flaw was found in the DSA implementation in
the JCE component of OpenJDK. A remote attacker able to make a Java
application generate DSA signatures on demand could possibly use this
flaw to extract certain information about the used key via a timing
side channel. (CVE-2017-10115)

Insufficient access control checks in ActivationID (CVE-2017-10107)

LDAPCertStore following referrals to non-LDAP URLs :

It was discovered that the LDAPCertStore class in the Security
component of OpenJDK followed LDAP referrals to arbitrary URLs. A
specially crafted LDAP referral URL could cause LDAPCertStore to
communicate with non-LDAP servers. (CVE-2017-10116)

JAR verifier incorrect handling of missing digest (CVE-2017-10067)

Reading of unprocessed image data in JPEGImageReader :

It was discovered that the JPEGImageReader implementation in the 2D
component of OpenJDK would, in certain cases, read all image data even
if it was not used later. A specially crafted image could cause a Java
application to temporarily use an excessive amount of CPU and memory.
(CVE-2017-10053)

Unbounded memory allocation in CodeSource deserialization
(CVE-2017-10109)

Unbounded memory allocation in BasicAttribute deserialization
(CVE-2017-10108)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-860.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.8.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/26");
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
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-1.8.0.141-1.b16.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.141-1.b16.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-demo-1.8.0.141-1.b16.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-devel-1.8.0.141-1.b16.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-headless-1.8.0.141-1.b16.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-javadoc-1.8.0.141-1.b16.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.141-1.b16.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-src-1.8.0.141-1.b16.32.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-debuginfo / etc");
}
