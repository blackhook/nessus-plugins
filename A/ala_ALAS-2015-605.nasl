#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-605.
#

include("compat.inc");

if (description)
{
  script_id(86636);
  script_version("2.3");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4903", "CVE-2015-4911");
  script_xref(name:"ALAS", value:"2015-605");
  script_xref(name:"RHSA", value:"2015:1920");

  script_name(english:"Amazon Linux AMI : java-1.7.0-openjdk (ALAS-2015-605)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple flaws were discovered in the CORBA, Libraries, RMI,
Serialization, and 2D components in OpenJDK. An untrusted Java
application or applet could use these flaws to completely bypass Java
sandbox restrictions. (CVE-2015-4835 , CVE-2015-4881 , CVE-2015-4843 ,
CVE-2015-4883 , CVE-2015-4860 , CVE-2015-4805 , CVE-2015-4844)

Multiple denial of service flaws were found in the JAXP component in
OpenJDK. A specially crafted XML file could cause a Java application
using JAXP to consume an excessive amount of CPU and memory when
parsed. (CVE-2015-4803 , CVE-2015-4893 , CVE-2015-4911)

It was discovered that the Security component in OpenJDK failed to
properly check if a certificate satisfied all defined constraints. In
certain cases, this could cause a Java application to accept an X.509
certificate which does not meet requirements of the defined policy.
(CVE-2015-4872)

Multiple flaws were found in the Libraries, 2D, CORBA, JAXP, JGSS, and
RMI components in OpenJDK. An untrusted Java application or applet
could use these flaws to bypass certain Java sandbox restrictions.
(CVE-2015-4806 , CVE-2015-4840 , CVE-2015-4882 , CVE-2015-4842 ,
CVE-2015-4734 , CVE-2015-4903)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-605.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.7.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-1.7.0.91-2.6.2.2.63.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.91-2.6.2.2.63.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-demo-1.7.0.91-2.6.2.2.63.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-devel-1.7.0.91-2.6.2.2.63.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-javadoc-1.7.0.91-2.6.2.2.63.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-src-1.7.0.91-2.6.2.2.63.amzn1")) flag++;

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
