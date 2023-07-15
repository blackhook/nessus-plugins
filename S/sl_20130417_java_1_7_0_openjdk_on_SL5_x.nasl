#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66018);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2013-0401",
    "CVE-2013-1488",
    "CVE-2013-1518",
    "CVE-2013-1537",
    "CVE-2013-1557",
    "CVE-2013-1558",
    "CVE-2013-1569",
    "CVE-2013-2383",
    "CVE-2013-2384",
    "CVE-2013-2415",
    "CVE-2013-2417",
    "CVE-2013-2419",
    "CVE-2013-2420",
    "CVE-2013-2421",
    "CVE-2013-2422",
    "CVE-2013-2423",
    "CVE-2013-2424",
    "CVE-2013-2426",
    "CVE-2013-2429",
    "CVE-2013-2430",
    "CVE-2013-2431",
    "CVE-2013-2436"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Scientific Linux Security Update : java-1.7.0-openjdk on SL5.x i386/x86_64 (20130417)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Multiple flaws were discovered in the font layout engine in the 2D
component. An untrusted Java application or applet could possibly use
these flaws to trigger Java Virtual Machine memory corruption.
(CVE-2013-1569, CVE-2013-2383, CVE-2013-2384)

Multiple improper permission check issues were discovered in the
Beans, Libraries, JAXP, and RMI components in OpenJDK. An untrusted
Java application or applet could use these flaws to bypass Java
sandbox restrictions. (CVE-2013-1558, CVE-2013-2422, CVE-2013-2436,
CVE-2013-1518, CVE-2013-1557)

The previous default value of the java.rmi.server.useCodebaseOnly
property permitted the RMI implementation to automatically load
classes from remotely specified locations. An attacker able to connect
to an application using RMI could use this flaw to make the
application execute arbitrary code. (CVE-2013-1537)

Note: The fix for CVE-2013-1537 changes the default value of the
property to true, restricting class loading to the local CLASSPATH and
locations specified in the java.rmi.server.codebase property.

The 2D component did not properly process certain images. An untrusted
Java application or applet could possibly use this flaw to trigger
Java Virtual Machine memory corruption. (CVE-2013-2420)

It was discovered that the Hotspot component did not properly handle
certain intrinsic frames, and did not correctly perform access checks
and MethodHandle lookups. An untrusted Java application or applet
could use these flaws to bypass Java sandbox restrictions.
(CVE-2013-2431, CVE-2013-2421, CVE-2013-2423)

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

This erratum also upgrades the OpenJDK package to IcedTea7 2.3.9.

All running instances of OpenJDK Java must be restarted for the update
to take effect.");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1304&L=scientific-linux-errata&T=0&P=1562
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7a60f47");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Reflection Type Confusion Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-1.7.0.19-2.3.9.1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.19-2.3.9.1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-demo-1.7.0.19-2.3.9.1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-devel-1.7.0.19-2.3.9.1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-javadoc-1.7.0.19-2.3.9.1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-src-1.7.0.19-2.3.9.1.el5_9")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-debuginfo / etc");
}
