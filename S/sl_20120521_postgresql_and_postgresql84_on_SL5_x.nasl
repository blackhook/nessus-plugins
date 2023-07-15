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
  script_id(61316);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-0866", "CVE-2012-0867", "CVE-2012-0868");

  script_name(english:"Scientific Linux Security Update : postgresql and postgresql84 on SL5.x, SL6.x i386/x86_64 (20120521)");
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
"PostgreSQL is an advanced object-relational database management system
(DBMS).

The pg_dump utility inserted object names literally into comments in
the SQL script it produces. An unprivileged database user could create
an object whose name includes a newline followed by a SQL command.
This SQL command might then be executed by a privileged user during
later restore of the backup dump, allowing privilege escalation.
(CVE-2012-0868)

When configured to do SSL certificate verification, PostgreSQL only
checked the first 31 characters of the certificate's Common Name
field. Depending on the configuration, this could allow an attacker to
impersonate a server or a client using a certificate from a trusted
Certificate Authority issued for a different name. (CVE-2012-0867)

CREATE TRIGGER did not do a permissions check on the trigger function
to be called. This could possibly allow an authenticated database user
to call a privileged trigger function on data of their choosing.
(CVE-2012-0866)

These updated packages upgrade PostgreSQL to version 8.4.11, which
fixes these issues as well as several data-corruption issues and
lesser non-security issues. Refer to the PostgreSQL Release Notes for
a full list of changes :

http://www.postgresql.org/docs/8.4/static/release.html

All PostgreSQL users are advised to upgrade to these updated packages,
which correct these issues. If the postgresql service is running, it
will be automatically restarted after installing this update."
  );
  # http://www.postgresql.org/docs/8.4/static/release.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/8.4/release.html"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1205&L=scientific-linux-errata&T=0&P=973
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d76d0787"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql84-debuginfo");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/21");
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
if (rpm_check(release:"SL5", reference:"postgresql84-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-contrib-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-debuginfo-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-devel-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-docs-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-libs-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plperl-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plpython-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-pltcl-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-python-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-server-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-tcl-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-test-8.4.11-1.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"postgresql-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-contrib-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-debuginfo-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-devel-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-docs-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-libs-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plperl-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plpython-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-pltcl-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-server-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-test-8.4.11-1.el6_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-debuginfo / etc");
}
