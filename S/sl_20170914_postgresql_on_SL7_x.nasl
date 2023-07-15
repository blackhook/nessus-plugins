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
  script_id(103244);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-7546", "CVE-2017-7547");

  script_name(english:"Scientific Linux Security Update : postgresql on SL7.x x86_64 (20170914)");
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
postgresql (9.2.23).

Security Fix(es) :

  - It was found that authenticating to a PostgreSQL
    database account with an empty password was possible
    despite libpq's refusal to send an empty password. A
    remote attacker could potentially use this flaw to gain
    access to database accounts with empty passwords.
    (CVE-2017-7546)

  - An authorization flaw was found in the way PostgreSQL
    handled access to the pg_user_mappings view on foreign
    servers. A remote, authenticated attacker could
    potentially use this flaw to retrieve passwords from the
    user mappings defined by the foreign server owners
    without actually having the privileges to do so.
    (CVE-2017-7547)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1709&L=scientific-linux-errata&F=&S=&P=1415
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b4b2335"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-contrib-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-debuginfo-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-devel-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-docs-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-libs-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-plperl-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-plpython-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-pltcl-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-server-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-static-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-test-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-upgrade-9.2.23-1.el7_4")) flag++;


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
