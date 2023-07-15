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
  script_id(61341);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2102");

  script_name(english:"Scientific Linux Security Update : mysql on SL6.x i386/x86_64 (20120620)");
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
"MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

A flaw was found in the way MySQL processed HANDLER READ NEXT
statements after deleting a record. A remote, authenticated attacker
could use this flaw to provide such requests, causing mysqld to crash.
This issue only caused a temporary denial of service, as mysqld was
automatically restarted after the crash. (CVE-2012-2102)

This update also adds the following enhancement :

  - The InnoDB storage engine is built-in for all
    architectures. This update adds InnoDB Plugin, the
    InnoDB storage engine as a plug-in for the 32-bit x86,
    AMD64, and Intel 64 architectures. The plug-in offers
    additional features and better performance than when
    using the built-in InnoDB storage engine. Refer to the
    MySQL documentation, linked to in the References
    section, for information about enabling the plug-in.

All MySQL users should upgrade to these updated packages, which add
this enhancement and contain a backported patch to correct this issue.
After installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=2810
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ba82b81"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
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
if (rpm_check(release:"SL6", reference:"mysql-5.1.61-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-bench-5.1.61-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-debuginfo-5.1.61-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-devel-5.1.61-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-embedded-5.1.61-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-embedded-devel-5.1.61-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-libs-5.1.61-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-server-5.1.61-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-test-5.1.61-4.el6")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
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
