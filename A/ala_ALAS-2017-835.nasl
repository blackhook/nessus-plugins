#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-835.
#

include("compat.inc");

if (description)
{
  script_id(100636);
  script_version("3.3");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2016-5542", "CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");
  script_xref(name:"ALAS", value:"2017-835");
  script_xref(name:"RHSA", value:"2017:1204");

  script_name(english:"Amazon Linux AMI : java-1.7.0-openjdk (ALAS-2017-835)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An untrusted library search path flaw was found in the JCE component
of

OpenJDK. A local attacker could possibly use this flaw to cause a Java

application using JCE to load an attacker-controlled library and hence
escalate

their privileges. (CVE-2017-3511)

It was found that the JAXP component of OpenJDK failed to correctly
enforce

parse tree size limits when parsing XML document. An attacker able to
make a

Java application parse a specially crafted XML document could use this
flaw to

make it consume an excessive amount of CPU and memory. (CVE-2017-3526)

It was discovered that the HTTP client implementation in the
Networking

component of OpenJDK could cache and re-use an NTLM authenticated
connection in

a different security context. A remote attacker could possibly use
this flaw to

make a Java application perform HTTP requests authenticated with
credentials of

a different user. (CVE-2017-3509)

It was discovered that the Security component of OpenJDK did not allow
users

to restrict the set of algorithms allowed for Jar integrity
verification. This

flaw could allow an attacker to modify content of the Jar file that
used weak

signing key or hash algorithm. (CVE-2017-3539)

Newline injection flaws were discovered in FTP and SMTP client
implementations

in the Networking component in OpenJDK. A remote attacker could
possibly use

these flaws to manipulate FTP or SMTP connections established by a
Java

application. (CVE-2017-3533 , CVE-2017-3544)

Note: This update adds support for the 'jdk.ntlm.cache' system
property which,

when set to false, prevents caching of NTLM connections and
authentications and

hence prevents this issue. However, caching remains enabled by
default.

Note: This updates extends the fix for CVE-2016-5542 released as part
of the

RHSA-2016-2658 erratum to no longer allow the MD5 hash algorithm
during the Jar

integrity verification by adding it to the jdk.jar.disabledAlgorithms
security

property."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-835.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.7.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-1.7.0.141-2.6.10.1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.141-2.6.10.1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-demo-1.7.0.141-2.6.10.1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-devel-1.7.0.141-2.6.10.1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-javadoc-1.7.0.141-2.6.10.1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-src-1.7.0.141-2.6.10.1.73.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-debuginfo / etc");
}
