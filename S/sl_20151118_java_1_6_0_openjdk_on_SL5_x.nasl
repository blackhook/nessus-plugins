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
  script_id(86938);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4835", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4903", "CVE-2015-4911");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-openjdk on SL5.x, SL6.x, SL7.x i386/x86_64 (20151118)");
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
"Multiple flaws were discovered in the CORBA, Libraries, RMI,
Serialization, and 2D components in OpenJDK. An untrusted Java
application or applet could use these flaws to completely bypass Java
sandbox restrictions. (CVE-2015-4835, CVE-2015-4881, CVE-2015-4843,
CVE-2015-4883, CVE-2015-4860, CVE-2015-4805, CVE-2015-4844)

Multiple denial of service flaws were found in the JAXP component in
OpenJDK. A specially crafted XML file could cause a Java application
using JAXP to consume an excessive amount of CPU and memory when
parsed. (CVE-2015-4803, CVE-2015-4893, CVE-2015-4911)

It was discovered that the Security component in OpenJDK failed to
properly check if a certificate satisfied all defined constraints. In
certain cases, this could cause a Java application to accept an X.509
certificate which does not meet requirements of the defined policy.
(CVE-2015-4872)

Multiple flaws were found in the Libraries, CORBA, JAXP, JGSS, and RMI
components in OpenJDK. An untrusted Java application or applet could
use these flaws to bypass certain Java sandbox restrictions.
(CVE-2015-4806, CVE-2015-4882, CVE-2015-4842, CVE-2015-4734,
CVE-2015-4903)

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1511&L=scientific-linux-errata&F=&S=&P=14793
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a938c6b"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-1.6.0.37-1.13.9.4.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.37-1.13.9.4.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-demo-1.6.0.37-1.13.9.4.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-devel-1.6.0.37-1.13.9.4.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.37-1.13.9.4.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-src-1.6.0.37-1.13.9.4.el5_11")) flag++;

if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-1.6.0.37-1.13.9.4.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.37-1.13.9.4.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-demo-1.6.0.37-1.13.9.4.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-devel-1.6.0.37-1.13.9.4.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.37-1.13.9.4.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-src-1.6.0.37-1.13.9.4.el6_7")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.37-1.13.9.4.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.37-1.13.9.4.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.37-1.13.9.4.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.37-1.13.9.4.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.37-1.13.9.4.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.37-1.13.9.4.el7_1")) flag++;


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
