#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1014 and 
# Oracle Linux Security Advisory ELSA-2013-1014 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68842);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/29");

  script_cve_id(
    "CVE-2013-1500",
    "CVE-2013-1571",
    "CVE-2013-2407",
    "CVE-2013-2412",
    "CVE-2013-2443",
    "CVE-2013-2444",
    "CVE-2013-2445",
    "CVE-2013-2446",
    "CVE-2013-2447",
    "CVE-2013-2448",
    "CVE-2013-2450",
    "CVE-2013-2452",
    "CVE-2013-2453",
    "CVE-2013-2455",
    "CVE-2013-2456",
    "CVE-2013-2457",
    "CVE-2013-2459",
    "CVE-2013-2461",
    "CVE-2013-2463",
    "CVE-2013-2465",
    "CVE-2013-2469",
    "CVE-2013-2470",
    "CVE-2013-2471",
    "CVE-2013-2472",
    "CVE-2013-2473"
  );
  script_bugtraq_id(
    60617,
    60618,
    60619,
    60620,
    60623,
    60627,
    60629,
    60632,
    60633,
    60634,
    60638,
    60639,
    60640,
    60641,
    60644,
    60645,
    60646,
    60647,
    60651,
    60653,
    60655,
    60656,
    60657,
    60658,
    60659
  );
  script_xref(name:"RHSA", value:"2013:1014");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"Oracle Linux 5 / 6 : java-1.6.0-openjdk (ELSA-2013-1014)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2013:1014 :

Updated java-1.6.0-openjdk packages that fix various security issues
are now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

Multiple flaws were discovered in the ImagingLib and the image
attribute, channel, layout and raster processing in the 2D component.
An untrusted Java application or applet could possibly use these flaws
to trigger Java Virtual Machine memory corruption. (CVE-2013-2470,
CVE-2013-2471, CVE-2013-2472, CVE-2013-2473, CVE-2013-2463,
CVE-2013-2465, CVE-2013-2469)

Integer overflow flaws were found in the way AWT processed certain
input. An attacker could use these flaws to execute arbitrary code
with the privileges of the user running an untrusted Java applet or
application. (CVE-2013-2459)

Multiple improper permission check issues were discovered in the Sound
and JMX components in OpenJDK. An untrusted Java application or applet
could use these flaws to bypass Java sandbox restrictions.
(CVE-2013-2448, CVE-2013-2457, CVE-2013-2453)

Multiple flaws in the Serialization, Networking, Libraries and CORBA
components can be exploited by an untrusted Java application or applet
to gain access to potentially sensitive information. (CVE-2013-2456,
CVE-2013-2447, CVE-2013-2455, CVE-2013-2452, CVE-2013-2443,
CVE-2013-2446)

It was discovered that the Hotspot component did not properly handle
out-of-memory errors. An untrusted Java application or applet could
possibly use these flaws to terminate the Java Virtual Machine.
(CVE-2013-2445)

It was discovered that the AWT component did not properly manage
certain resources and that the ObjectStreamClass of the Serialization
component did not properly handle circular references. An untrusted
Java application or applet could possibly use these flaws to cause a
denial of service. (CVE-2013-2444, CVE-2013-2450)

It was discovered that the Libraries component contained certain
errors related to XML security and the class loader. A remote attacker
could possibly exploit these flaws to bypass intended security
mechanisms or disclose potentially sensitive information and cause a
denial of service. (CVE-2013-2407, CVE-2013-2461)

It was discovered that JConsole did not properly inform the user when
establishing an SSL connection failed. An attacker could exploit this
flaw to gain access to potentially sensitive information.
(CVE-2013-2412)

It was found that documentation generated by Javadoc was vulnerable to
a frame injection attack. If such documentation was accessible over a
network, and a remote attacker could trick a user into visiting a
specially crafted URL, it would lead to arbitrary web content being
displayed next to the documentation. This could be used to perform a
phishing attack by providing frame content that spoofed a login form
on the site hosting the vulnerable documentation. (CVE-2013-1571)

It was discovered that the 2D component created shared memory segments
with insecure permissions. A local attacker could use this flaw to
read or write to the shared memory segment. (CVE-2013-1500)

Red Hat would like to thank US-CERT for reporting CVE-2013-1571, and
Tim Brown for reporting CVE-2013-1500. US-CERT acknowledges Oracle as
the original reporter of CVE-2013-1571.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2013-July/003560.html");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2013-July/003561.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.6.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2473");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-1.6.0.0-1.41.1.11.11.90.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.41.1.11.11.90.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.41.1.11.11.90.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.41.1.11.11.90.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.41.1.11.11.90.0.1.el5_9")) flag++;

if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-1.6.0.0-1.62.1.11.11.90.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.62.1.11.11.90.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.62.1.11.11.90.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.62.1.11.11.90.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.62.1.11.11.90.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc");
}