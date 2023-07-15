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
  script_id(85499);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-6568", "CVE-2015-0374", "CVE-2015-0381", "CVE-2015-0382", "CVE-2015-0391", "CVE-2015-0411", "CVE-2015-0432", "CVE-2015-0433", "CVE-2015-0441", "CVE-2015-0499", "CVE-2015-0501", "CVE-2015-0505", "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573", "CVE-2015-2582", "CVE-2015-2620", "CVE-2015-2643", "CVE-2015-2648", "CVE-2015-4737", "CVE-2015-4752", "CVE-2015-4757");

  script_name(english:"Scientific Linux Security Update : mysql55-mysql on SL5.x i386/x86_64 (20150817)");
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
"This update fixes several vulnerabilities in the MySQL database
server. (CVE-2014-6568, CVE-2015-0374, CVE-2015-0381, CVE-2015-0382,
CVE-2015-0391, CVE-2015-0411, CVE-2015-0432, CVE-2015-0433,
CVE-2015-0441, CVE-2015-0499, CVE-2015-0501, CVE-2015-0505,
CVE-2015-2568, CVE-2015-2571, CVE-2015-2573, CVE-2015-2582,
CVE-2015-2620, CVE-2015-2643, CVE-2015-2648, CVE-2015-4737,
CVE-2015-4752, CVE-2015-4757)

After installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=16594
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?defd4d43"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql55-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql55-mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql55-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql55-mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql55-mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql55-mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql55-mysql-test");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/18");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-5.5.45-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-bench-5.5.45-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-debuginfo-5.5.45-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-devel-5.5.45-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-libs-5.5.45-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-server-5.5.45-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-test-5.5.45-1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql55-mysql / mysql55-mysql-bench / mysql55-mysql-debuginfo / etc");
}
