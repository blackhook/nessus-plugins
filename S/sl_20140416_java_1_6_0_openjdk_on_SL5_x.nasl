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
  script_id(73588);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-5797", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-1876", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2403", "CVE-2014-2412", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-openjdk on SL5.x, SL6.x i386/x86_64 (20140416)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An input validation flaw was discovered in the medialib library in the
2D component. A specially crafted image could trigger Java Virtual
Machine memory corruption when processed. A remote attacker, or an
untrusted Java application or applet, could possibly use this flaw to
execute arbitrary code with the privileges of the user running the
Java Virtual Machine. (CVE-2014-0429)

Multiple flaws were discovered in the Hotspot and 2D components in
OpenJDK. An untrusted Java application or applet could use these flaws
to trigger Java Virtual Machine memory corruption and possibly bypass
Java sandbox restrictions. (CVE-2014-0456, CVE-2014-2397,
CVE-2014-2421)

Multiple improper permission check issues were discovered in the
Libraries component in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass Java sandbox restrictions.
(CVE-2014-0457, CVE-2014-0461)

Multiple improper permission check issues were discovered in the AWT,
JAX- WS, JAXB, Libraries, and Sound components in OpenJDK. An
untrusted Java application or applet could use these flaws to bypass
certain Java sandbox restrictions. (CVE-2014-2412, CVE-2014-0451,
CVE-2014-0458, CVE-2014-2423, CVE-2014-0452, CVE-2014-2414,
CVE-2014-0446, CVE-2014-2427)

Multiple flaws were identified in the Java Naming and Directory
Interface (JNDI) DNS client. These flaws could make it easier for a
remote attacker to perform DNS spoofing attacks. (CVE-2014-0460)

It was discovered that the JAXP component did not properly prevent
access to arbitrary files when a SecurityManager was present. This
flaw could cause a Java application using JAXP to leak sensitive
information, or affect application availability. (CVE-2014-2403)

It was discovered that the Security component in OpenJDK could leak
some timing information when performing PKCS#1 unpadding. This could
possibly lead to the disclosure of some information that was meant to
be protected by encryption. (CVE-2014-0453)

It was discovered that the fix for CVE-2013-5797 did not properly
resolve input sanitization flaws in javadoc. When javadoc
documentation was generated from an untrusted Java source code and
hosted on a domain not controlled by the code author, these issues
could make it easier to perform cross-site scripting (XSS) attacks.
(CVE-2014-2398)

An insecure temporary file use flaw was found in the way the unpack200
utility created log files. A local attacker could possibly use this
flaw to perform a symbolic link attack and overwrite arbitrary files
with the privileges of the user running unpack200. (CVE-2014-1876)

This update also fixes the following bug :

  - The OpenJDK update to IcedTea version 1.13 introduced a
    regression related to the handling of the
    jdk_version_info variable. This variable was not
    properly zeroed out before being passed to the Java
    Virtual Machine, resulting in a memory leak in the
    java.lang.ref.Finalizer class. This update fixes this
    issue, and memory leaks no longer occur.

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1404&L=scientific-linux-errata&T=0&P=1717
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15845b97"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-1.6.0.0-5.1.13.3.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-5.1.13.3.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-5.1.13.3.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-5.1.13.3.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-5.1.13.3.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-src-1.6.0.0-5.1.13.3.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-1.6.0.0-5.1.13.3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-5.1.13.3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-demo-1.6.0.0-5.1.13.3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-devel-1.6.0.0-5.1.13.3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-5.1.13.3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-src-1.6.0.0-5.1.13.3.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-debuginfo / etc");
}