#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(111806);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2017-10268", "CVE-2017-10378", "CVE-2017-10379", "CVE-2017-10384", "CVE-2017-3636", "CVE-2017-3641", "CVE-2017-3651", "CVE-2017-3653", "CVE-2018-2562", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668", "CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2767", "CVE-2018-2771", "CVE-2018-2781", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819");

  script_name(english:"Scientific Linux Security Update : mariadb on SL7.x x86_64 (20180816)");
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
"The following packages have been upgraded to a later upstream version:
mariadb (5.5.60).

Security Fix(es) :

  - mysql: Client programs unspecified vulnerability (CPU
    Jul 2017) (CVE-2017-3636)

  - mysql: Server: DML unspecified vulnerability (CPU Jul
    2017) (CVE-2017-3641)

  - mysql: Client mysqldump unspecified vulnerability (CPU
    Jul 2017) (CVE-2017-3651)

  - mysql: Server: Replication unspecified vulnerability
    (CPU Oct 2017) (CVE-2017-10268)

  - mysql: Server: Optimizer unspecified vulnerability (CPU
    Oct 2017) (CVE-2017-10378)

  - mysql: Client programs unspecified vulnerability (CPU
    Oct 2017) (CVE-2017-10379)

  - mysql: Server: DDL unspecified vulnerability (CPU Oct
    2017) (CVE-2017-10384)

  - mysql: Server: Partition unspecified vulnerability (CPU
    Jan 2018) (CVE-2018-2562)

  - mysql: Server: DDL unspecified vulnerability (CPU Jan
    2018) (CVE-2018-2622)

  - mysql: Server: Optimizer unspecified vulnerability (CPU
    Jan 2018) (CVE-2018-2640)

  - mysql: Server: Optimizer unspecified vulnerability (CPU
    Jan 2018) (CVE-2018-2665)

  - mysql: Server: Optimizer unspecified vulnerability (CPU
    Jan 2018) (CVE-2018-2668)

  - mysql: Server: Replication unspecified vulnerability
    (CPU Apr 2018) (CVE-2018-2755)

  - mysql: Client programs unspecified vulnerability (CPU
    Apr 2018) (CVE-2018-2761)

  - mysql: Server: Locking unspecified vulnerability (CPU
    Apr 2018) (CVE-2018-2771)

  - mysql: Server: Optimizer unspecified vulnerability (CPU
    Apr 2018) (CVE-2018-2781)

  - mysql: Server: DDL unspecified vulnerability (CPU Apr
    2018) (CVE-2018-2813)

  - mysql: Server: DDL unspecified vulnerability (CPU Apr
    2018) (CVE-2018-2817)

  - mysql: InnoDB unspecified vulnerability (CPU Apr 2018)
    (CVE-2018-2819)

  - mysql: Server: DDL unspecified vulnerability (CPU Jul
    2017) (CVE-2017-3653)

  - mysql: use of SSL/TLS not enforced in libmysqld (Return
    of BACKRONYM) (CVE-2018-2767)

Bug Fix(es) :

  - Previously, the mysqladmin tool waited for an inadequate
    length of time if the socket it listened on did not
    respond in a specific way. Consequently, when the socket
    was used while the MariaDB server was starting, the
    mariadb service became unresponsive for a long time.
    With this update, the mysqladmin timeout has been
    shortened to 2 seconds. As a result, the mariadb service
    either starts or fails but no longer hangs in the
    described situation."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1808&L=scientific-linux-errata&F=&S=&P=2075
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b3ca8f6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-bench-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-debuginfo-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-devel-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-embedded-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-embedded-devel-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-libs-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-server-5.5.60-1.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-test-5.5.60-1.el7_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb / mariadb-bench / mariadb-debuginfo / mariadb-devel / etc");
}
