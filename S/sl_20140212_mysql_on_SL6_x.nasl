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
  script_id(72477);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-5908", "CVE-2014-0001", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0437");

  script_name(english:"Scientific Linux Security Update : mysql on SL6.x i386/x86_64 (20140212)");
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
"(CVE-2014-0386, CVE-2014-0393, CVE-2014-0401, CVE-2014-0402,
CVE-2014-0412, CVE-2014-0437, CVE-2013-5908)

A buffer overflow flaw was found in the way the MySQL command line
client tool (mysql) processed excessively long version strings. If a
user connected to a malicious MySQL server via the mysql client, the
server could use this flaw to crash the mysql client or, potentially,
execute arbitrary code as the user running the mysql client.
(CVE-2014-0001)

This update also fixes the following bug :

  - Prior to this update, MySQL did not check whether a
    MySQL socket was actually being used by any process
    before starting the mysqld service. If a particular
    mysqld service did not exit cleanly while a socket was
    being used by a process, this socket was considered to
    be still in use during the next start-up of this
    service, which resulted in a failure to start the
    service up. With this update, if a socket exists but is
    not used by any process, it is ignored during the mysqld
    service start-up.

After installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1402&L=scientific-linux-errata&T=0&P=1565
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce630790"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/13");
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
if (rpm_check(release:"SL6", reference:"mysql-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-bench-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-debuginfo-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-devel-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-embedded-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-embedded-devel-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-libs-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-server-5.1.73-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-test-5.1.73-3.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-debuginfo / mysql-devel / etc");
}
