#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-283.
#

include("compat.inc");

if (description)
{
  script_id(72301);
  script_version("1.7");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5896", "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0376", "CVE-2014-0411", "CVE-2014-0416", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0428");
  script_xref(name:"ALAS", value:"2014-283");
  script_xref(name:"RHSA", value:"2014:0097");

  script_name(english:"Amazon Linux AMI : java-1.6.0-openjdk (ALAS-2014-283)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An input validation flaw was discovered in the font layout engine in
the 2D component. A specially crafted font file could trigger a Java
Virtual Machine memory corruption when processed. An untrusted Java
application or applet could possibly use this flaw to bypass Java
sandbox restrictions. (CVE-2013-5907)

Multiple improper permission check issues were discovered in the CORBA
and JNDI components in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass Java sandbox restrictions.
(CVE-2014-0428 , CVE-2014-0422)

Multiple improper permission check issues were discovered in the
Serviceability, Security, CORBA, JAAS, JAXP, and Networking components
in OpenJDK. An untrusted Java application or applet could use these
flaws to bypass certain Java sandbox restrictions. (CVE-2014-0373 ,
CVE-2013-5878 , CVE-2013-5910 , CVE-2013-5896 , CVE-2013-5884 ,
CVE-2014-0416 , CVE-2014-0376 , CVE-2014-0368)

It was discovered that the Beans component did not restrict processing
of XML external entities. This flaw could cause a Java application
using Beans to leak sensitive information, or affect application
availability. (CVE-2014-0423)

It was discovered that the JSSE component could leak timing
information during the TLS/SSL handshake. This could possibly lead to
a disclosure of information about the used encryption keys.
(CVE-2014-0411)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-283.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.6.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-1.6.0.0-66.1.13.1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-66.1.13.1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-demo-1.6.0.0-66.1.13.1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-devel-1.6.0.0-66.1.13.1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-66.1.13.1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-src-1.6.0.0-66.1.13.1.62.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-debuginfo / etc");
}
