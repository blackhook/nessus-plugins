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
  script_id(70705);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0255", "CVE-2013-1900");

  script_name(english:"Scientific Linux Security Update : postgresql and postgresql84 on SL5.x, SL6.x i386/x86_64 (20131029)");
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
"An array index error, leading to a heap-based out-of-bounds buffer
read flaw, was found in the way PostgreSQL performed certain error
processing using enumeration types. An unprivileged database user
could issue a specially crafted SQL query that, when processed by the
server component of the PostgreSQL service, would lead to a denial of
service (daemon crash) or disclosure of certain portions of server
memory. (CVE-2013-0255)

A flaw was found in the way the pgcrypto contrib module of PostgreSQL
(re)initialized its internal random number generator. This could lead
to random numbers with less bits of entropy being used by certain
pgcrypto functions, possibly allowing an attacker to conduct other
attacks. (CVE-2013-1900)

These updated packages upgrade PostgreSQL to version 8.4.18, which
fixes these issues as well as several non-security issues. Refer to
the PostgreSQL Release Notes for a full list of changes :

http://www.postgresql.org/docs/8.4/static/release-8-4-18.html

After installing this update, it is advisable to rebuild, using the
REINDEX command, Generalized Search Tree (GiST) indexes that meet one
or more of the following conditions :

    - GiST indexes on box, polygon, circle, or point columns

    - GiST indexes for variable-width data types, that is
      text, bytea, bit, and numeric

    - GiST multi-column indexes

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # http://www.postgresql.org/docs/8.4/static/release-8-4-18.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/8.4/static/release-8-4-18.html"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=3018
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b692ed37"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"postgresql84-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-contrib-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-debuginfo-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-devel-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-docs-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-libs-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plperl-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plpython-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-pltcl-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-python-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-server-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-tcl-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-test-8.4.18-1.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"postgresql-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-contrib-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-debuginfo-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-devel-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-docs-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-libs-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plperl-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plpython-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-pltcl-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-server-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-test-8.4.18-1.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-debuginfo / etc");
}
