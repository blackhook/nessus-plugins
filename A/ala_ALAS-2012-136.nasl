#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-136.
#

include("compat.inc");

if (description)
{
  script_id(69626);
  script_version("1.11");
  script_cvs_date("Date: 2019/10/16 10:34:21");

  script_cve_id("CVE-2012-3216", "CVE-2012-4416", "CVE-2012-5068", "CVE-2012-5075", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5085", "CVE-2012-5086");
  script_xref(name:"ALAS", value:"2012-136");
  script_xref(name:"RHSA", value:"2012:1384");

  script_name(english:"Amazon Linux AMI : java-1.6.0-openjdk (ALAS-2012-136) (ROBOT)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple improper permission check issues were discovered in the
Beans, Swing, and JMX components in OpenJDK. An untrusted Java
application or applet could use these flaws to bypass Java sandbox
restrictions. (CVE-2012-5086 , CVE-2012-5084 , CVE-2012-5089)

Multiple improper permission check issues were discovered in the
Scripting, JMX, Concurrency, Libraries, and Security components in
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2012-5068 ,
CVE-2012-5071 , CVE-2012-5069 , CVE-2012-5073 , CVE-2012-5072)

It was discovered that java.util.ServiceLoader could create an
instance of an incompatible class while performing provider lookup. An
untrusted Java application or applet could use this flaw to bypass
certain Java sandbox restrictions. (CVE-2012-5079)

It was discovered that the Java Secure Socket Extension (JSSE) SSL/TLS
implementation did not properly handle handshake records containing an
overly large data length value. An unauthenticated, remote attacker
could possibly use this flaw to cause an SSL/TLS server to terminate
with an exception. (CVE-2012-5081)

It was discovered that the JMX component in OpenJDK could perform
certain actions in an insecure manner. An untrusted Java application
or applet could possibly use this flaw to disclose sensitive
information. (CVE-2012-5075)

A bug in the Java HotSpot Virtual Machine optimization code could
cause it to not perform array initialization in certain cases. An
untrusted Java application or applet could use this flaw to disclose
portions of the virtual machine's memory. (CVE-2012-4416)

It was discovered that the SecureRandom class did not properly protect
against the creation of multiple seeders. An untrusted Java
application or applet could possibly use this flaw to disclose
sensitive information. (CVE-2012-5077)

It was discovered that the java.io.FilePermission class exposed the
hash code of the canonicalized path name. An untrusted Java
application or applet could possibly use this flaw to determine
certain system paths, such as the current working directory.
(CVE-2012-3216)

This update disables Gopher protocol support in the java.net package
by default. Gopher support can be enabled by setting the newly
introduced property, 'jdk.net.registerGopherProtocol', to true.
(CVE-2012-5085)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-136.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.6.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-1.6.0.0-53.1.11.5.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-53.1.11.5.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-demo-1.6.0.0-53.1.11.5.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-devel-1.6.0.0-53.1.11.5.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-53.1.11.5.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-src-1.6.0.0-53.1.11.5.47.amzn1")) flag++;

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
