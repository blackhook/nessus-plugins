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
  script_id(101884);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10078", "CVE-2017-10081", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10135", "CVE-2017-10193", "CVE-2017-10198");

  script_name(english:"Scientific Linux Security Update : java-1.8.0-openjdk on SL6.x, SL7.x i386/x86_64 (20170720)");
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
"Security Fix(es) :

  - It was discovered that the DCG implementation in the RMI
    component of OpenJDK failed to correctly handle
    references. A remote attacker could possibly use this
    flaw to execute arbitrary code with the privileges of
    RMI registry or a Java RMI application. (CVE-2017-10102)

  - Multiple flaws were discovered in the RMI, JAXP,
    ImageIO, Libraries, AWT, Hotspot, and Security
    components in OpenJDK. An untrusted Java application or
    applet could use these flaws to completely bypass Java
    sandbox restrictions. (CVE-2017-10107, CVE-2017-10096,
    CVE-2017-10101, CVE-2017-10089, CVE-2017-10090,
    CVE-2017-10087, CVE-2017-10111, CVE-2017-10110,
    CVE-2017-10074, CVE-2017-10067)

  - It was discovered that the LDAPCertStore class in the
    Security component of OpenJDK followed LDAP referrals to
    arbitrary URLs. A specially crafted LDAP referral URL
    could cause LDAPCertStore to communicate with non-LDAP
    servers. (CVE-2017-10116)

  - It was discovered that the Nashorn JavaScript engine in
    the Scripting component of OpenJDK could allow scripts
    to access Java APIs even when access to Java APIs was
    disabled. An untrusted JavaScript executed by Nashorn
    could use this flaw to bypass intended restrictions.
    (CVE-2017-10078)

  - It was discovered that the Security component of OpenJDK
    could fail to properly enforce restrictions defined for
    processing of X.509 certificate chains. A remote
    attacker could possibly use this flaw to make Java
    accept certificate using one of the disabled algorithms.
    (CVE-2017-10198)

  - A covert timing channel flaw was found in the DSA
    implementation in the JCE component of OpenJDK. A remote
    attacker able to make a Java application generate DSA
    signatures on demand could possibly use this flaw to
    extract certain information about the used key via a
    timing side channel. (CVE-2017-10115)

  - A covert timing channel flaw was found in the PKCS#8
    implementation in the JCE component of OpenJDK. A remote
    attacker able to make a Java application repeatedly
    compare PKCS#8 key against an attacker controlled value
    could possibly use this flaw to determine the key via a
    timing side channel. (CVE-2017-10135)

  - It was discovered that the BasicAttribute and CodeSource
    classes in OpenJDK did not limit the amount of memory
    allocated when creating object instances from a
    serialized form. A specially crafted serialized input
    stream could cause Java to consume an excessive amount
    of memory. (CVE-2017-10108, CVE-2017-10109)

  - Multiple flaws were found in the Hotspot and Security
    components in OpenJDK. An untrusted Java application or
    applet could use these flaws to bypass certain Java
    sandbox restrictions. (CVE-2017-10081, CVE-2017-10193)

  - It was discovered that the JPEGImageReader
    implementation in the 2D component of OpenJDK would, in
    certain cases, read all image data even if it was not
    used later. A specially crafted image could cause a Java
    application to temporarily use an excessive amount of
    CPU and memory. (CVE-2017-10053)

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1707&L=scientific-linux-errata&F=&S=&P=10218
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4883d92"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-accessibility-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-1.8.0.141-2.b16.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-debug-1.8.0.141-2.b16.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.141-2.b16.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-demo-1.8.0.141-2.b16.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.141-2.b16.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-devel-1.8.0.141-2.b16.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.141-2.b16.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-headless-1.8.0.141-2.b16.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.141-2.b16.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.141-2.b16.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.141-2.b16.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-src-1.8.0.141-2.b16.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-src-debug-1.8.0.141-2.b16.el6_9")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.141-1.b16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.141-1.b16.el7_3")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
}
