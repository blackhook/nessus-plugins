#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0770 and 
# Oracle Linux Security Advisory ELSA-2013-0770 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68815);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0401", "CVE-2013-1488", "CVE-2013-1518", "CVE-2013-1537", "CVE-2013-1557", "CVE-2013-1558", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2415", "CVE-2013-2417", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2424", "CVE-2013-2426", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431");
  script_bugtraq_id(58504, 58507, 59131, 59141, 59153, 59159, 59165, 59166, 59167, 59170, 59179, 59184, 59187, 59190, 59194, 59206, 59212, 59219, 59228, 59243);
  script_xref(name:"RHSA", value:"2013:0770");

  script_name(english:"Oracle Linux 5 / 6 : java-1.6.0-openjdk (ELSA-2013-0770)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0770 :

Updated java-1.6.0-openjdk packages that fix various security issues
are now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

Multiple flaws were discovered in the font layout engine in the 2D
component. An untrusted Java application or applet could possibly use
these flaws to trigger Java Virtual Machine memory corruption.
(CVE-2013-1569, CVE-2013-2383, CVE-2013-2384)

Multiple improper permission check issues were discovered in the
Beans, Libraries, JAXP, and RMI components in OpenJDK. An untrusted
Java application or applet could use these flaws to bypass Java
sandbox restrictions. (CVE-2013-1558, CVE-2013-2422, CVE-2013-1518,
CVE-2013-1557)

The previous default value of the java.rmi.server.useCodebaseOnly
property permitted the RMI implementation to automatically load
classes from remotely specified locations. An attacker able to connect
to an application using RMI could use this flaw to make the
application execute arbitrary code. (CVE-2013-1537)

Note: The fix for CVE-2013-1537 changes the default value of the
property to true, restricting class loading to the local CLASSPATH and
locations specified in the java.rmi.server.codebase property. Refer to
Red Hat Bugzilla bug 952387 for additional details.

The 2D component did not properly process certain images. An untrusted
Java application or applet could possibly use this flaw to trigger
Java Virtual Machine memory corruption. (CVE-2013-2420)

It was discovered that the Hotspot component did not properly handle
certain intrinsic frames, and did not correctly perform MethodHandle
lookups. An untrusted Java application or applet could use these flaws
to bypass Java sandbox restrictions. (CVE-2013-2431, CVE-2013-2421)

It was discovered that JPEGImageReader and JPEGImageWriter in the
ImageIO component did not protect against modification of their state
while performing certain native code operations. An untrusted Java
application or applet could possibly use these flaws to trigger Java
Virtual Machine memory corruption. (CVE-2013-2429, CVE-2013-2430)

The JDBC driver manager could incorrectly call the toString() method
in JDBC drivers, and the ConcurrentHashMap class could incorrectly
call the defaultReadObject() method. An untrusted Java application or
applet could possibly use these flaws to bypass Java sandbox
restrictions. (CVE-2013-1488, CVE-2013-2426)

The sun.awt.datatransfer.ClassLoaderObjectInputStream class may
incorrectly invoke the system class loader. An untrusted Java
application or applet could possibly use this flaw to bypass certain
Java sandbox restrictions. (CVE-2013-0401)

Flaws were discovered in the Network component's InetAddress
serialization, and the 2D component's font handling. An untrusted Java
application or applet could possibly use these flaws to crash the Java
Virtual Machine. (CVE-2013-2417, CVE-2013-2419)

The MBeanInstantiator class implementation in the OpenJDK JMX
component did not properly check class access before creating new
instances. An untrusted Java application or applet could use this flaw
to create instances of non-public classes. (CVE-2013-2424)

It was discovered that JAX-WS could possibly create temporary files
with insecure permissions. A local attacker could use this flaw to
access temporary files created by an application using JAX-WS.
(CVE-2013-2415)

This erratum also upgrades the OpenJDK package to IcedTea6 1.11.10.
Refer to the NEWS file, linked to in the References, for further
information.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-April/003432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-April/003439.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Driver Manager Privileged toString() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-1.6.0.0-1.40.1.11.11.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.40.1.11.11.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.40.1.11.11.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.40.1.11.11.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.40.1.11.11.0.1.el5_9")) flag++;

if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-1.6.0.0-1.61.1.11.11.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.61.1.11.11.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.61.1.11.11.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.61.1.11.11.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.61.1.11.11.el6_4")) flag++;


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
