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
  script_id(79304);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-2494", "CVE-2014-4207", "CVE-2014-4243", "CVE-2014-4258", "CVE-2014-4260", "CVE-2014-4274", "CVE-2014-4287", "CVE-2014-6463", "CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6484", "CVE-2014-6505", "CVE-2014-6507", "CVE-2014-6520", "CVE-2014-6530", "CVE-2014-6551", "CVE-2014-6555", "CVE-2014-6559");

  script_name(english:"Scientific Linux Security Update : mariadb on SL7.x x86_64 (20141117)");
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
"This update fixes several vulnerabilities in the MariaDB database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory page (CVE-2014-2494, CVE-2014-4207,
CVE-2014-4243, CVE-2014-4258, CVE-2014-4260, CVE-2014-4287,
CVE-2014-4274, CVE-2014-6463, CVE-2014-6464, CVE-2014-6469,
CVE-2014-6484, CVE-2014-6505, CVE-2014-6507, CVE-2014-6520,
CVE-2014-6530, CVE-2014-6551, CVE-2014-6555, CVE-2014-6559)

After installing this update, the MariaDB server daemon (mysqld) will
be restarted automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=3203
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?928039cd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/18");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-bench-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-debuginfo-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-devel-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-embedded-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-embedded-devel-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-libs-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-server-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-test-5.5.40-1.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb / mariadb-bench / mariadb-debuginfo / mariadb-devel / etc");
}
