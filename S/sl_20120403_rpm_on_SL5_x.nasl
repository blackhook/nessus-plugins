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
  script_id(61294);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815");

  script_name(english:"Scientific Linux Security Update : rpm on SL5.x, SL6.x i386/x86_64 (20120403)");
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
"The RPM Package Manager (RPM) is a command-line driven package
management system capable of installing, uninstalling, verifying,
querying, and updating software packages.

Multiple flaws were found in the way RPM parsed package file headers.
An attacker could create a specially crafted RPM package that, when
its package header was accessed, or during package signature
verification, could cause an application using the RPM library (such
as the rpm command line tool, or the yum and up2date package managers)
to crash or, potentially, execute arbitrary code. (CVE-2012-0060,
CVE-2012-0061, CVE-2012-0815)

Note: Although an RPM package can, by design, execute arbitrary code
when installed, this issue would allow a specially crafted RPM package
to execute arbitrary code before its digital signature has been
verified.

All RPM users should upgrade to these updated packages, which contain
a backported patch to correct these issues. All running applications
linked against the RPM library must be restarted for this update to
take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1204&L=scientific-linux-errata&T=0&P=190
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3fd3181"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:popt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rpm-python");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"popt-1.10.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-apidocs-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-build-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-debuginfo-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-devel-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-libs-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-python-4.4.2.3-28.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"rpm-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-apidocs-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-build-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-cron-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-debuginfo-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-devel-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-libs-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-python-4.8.0-19.el6_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "popt / rpm / rpm-apidocs / rpm-build / rpm-cron / rpm-debuginfo / etc");
}
