#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-88.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69695);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id(
    "CVE-2012-1711",
    "CVE-2012-1713",
    "CVE-2012-1716",
    "CVE-2012-1717",
    "CVE-2012-1718",
    "CVE-2012-1723",
    "CVE-2012-1724"
  );
  script_xref(name:"ALAS", value:"2012-88");
  script_xref(name:"RHSA", value:"2012:0729");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Amazon Linux AMI : java-1.6.0-openjdk (ALAS-2012-88)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Multiple flaws were discovered in the CORBA (Common Object Request
Broker Architecture) implementation in Java. A malicious Java
application or applet could use these flaws to bypass Java sandbox
restrictions or modify immutable object data. (CVE-2012-1711 ,
CVE-2012-1719)

It was discovered that the SynthLookAndFeel class from Swing did not
properly prevent access to certain UI elements from outside the
current application context. A malicious Java application or applet
could use this flaw to crash the Java Virtual Machine, or bypass Java
sandbox restrictions. (CVE-2012-1716)

Multiple flaws were discovered in the font manager's layout lookup
implementation. A specially crafted font file could cause the Java
Virtual Machine to crash or, possibly, execute arbitrary code with the
privileges of the user running the virtual machine. (CVE-2012-1713)

Multiple flaws were found in the way the Java HotSpot Virtual Machine
verified the bytecode of the class file to be executed. A specially
crafted Java application or applet could use these flaws to crash the
Java Virtual Machine, or bypass Java sandbox restrictions.
(CVE-2012-1723 , CVE-2012-1725)

It was discovered that the Java XML parser did not properly handle
certain XML documents. An attacker able to make a Java application
parse a specially crafted XML file could use this flaw to make the XML
parser enter an infinite loop. (CVE-2012-1724)

It was discovered that the Java security classes did not properly
handle Certificate Revocation Lists (CRL). CRL containing entries with
duplicate certificate serial numbers could have been ignored.
(CVE-2012-1718)

It was discovered that various classes of the Java Runtime library
could create temporary files with insecure permissions. A local
attacker could use this flaw to gain access to the content of such
temporary files. (CVE-2012-1717)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2012-88.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update java-1.6.0-openjdk' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

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
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-1.6.0.0-52.1.11.3.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-52.1.11.3.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-demo-1.6.0.0-52.1.11.3.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-devel-1.6.0.0-52.1.11.3.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-52.1.11.3.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-src-1.6.0.0-52.1.11.3.45.amzn1")) flag++;

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
