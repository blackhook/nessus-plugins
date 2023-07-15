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
  script_id(62109);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-3488");

  script_name(english:"Scientific Linux Security Update : postgresql on SL5.x i386/x86_64 (20120913)");
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
"It was found that the optional PostgreSQL xml2 contrib module allowed
local files and remote URLs to be read and written to with the
privileges of the database server when parsing Extensible Stylesheet
Language Transformations (XSLT). An unprivileged database user could
use this flaw to read and write to local files (such as the database's
configuration files) and remote URLs they would otherwise not have
access to by issuing a specially crafted SQL query. (CVE-2012-3488)

We would like to thank the PostgreSQL project for reporting this
issue. Upstream acknowledges Peter Eisentraut as the original
reporter.

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=1883
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54dd8603"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/15");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"postgresql-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-contrib-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-devel-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-docs-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-libs-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-pl-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-python-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-server-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-tcl-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-test-8.1.23-6.el5_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
