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
  script_id(62108);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-3488", "CVE-2012-3489");

  script_name(english:"Scientific Linux Security Update : postgresql and postgresql84 on SL5.x, SL6.x i386/x86_64 (20120913)");
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

It was found that the 'xml' data type allowed local files and remote
URLs to be read with the privileges of the database server to resolve
DTD and entity references in the provided XML. An unprivileged
database user could use this flaw to read local files they would
otherwise not have access to by issuing a specially crafted SQL query.
Note that the full contents of the files were not returned, but
portions could be displayed to the user via error messages.
(CVE-2012-3489)

We would like to thank the PostgreSQL project for reporting these
issues. Upstream acknowledges Peter Eisentraut as the original
reporter of CVE-2012-3488, and Noah Misch as the original reporter of
CVE-2012-3489.

These updated packages upgrade PostgreSQL to version 8.4.13. Refer to
the PostgreSQL Release Notes for a list of changes :

http://www.postgresql.org/docs/8.4/static/release-8-4-13.html

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # http://www.postgresql.org/docs/8.4/static/release-8-4-13.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/8.4/release-8-4-13.html"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=2138
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8085d421"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84-test");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"postgresql84-8.4.13-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-contrib-8.4.13-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-devel-8.4.13-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-docs-8.4.13-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-libs-8.4.13-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plperl-8.4.13-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plpython-8.4.13-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-pltcl-8.4.13-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-python-8.4.13-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-server-8.4.13-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-tcl-8.4.13-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-test-8.4.13-1.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"postgresql-8.4.13-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-contrib-8.4.13-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-devel-8.4.13-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-docs-8.4.13-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-libs-8.4.13-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plperl-8.4.13-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plpython-8.4.13-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-pltcl-8.4.13-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-server-8.4.13-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-test-8.4.13-1.el6_3")) flag++;


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
