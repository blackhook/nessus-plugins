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
  script_id(84540);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167");

  script_name(english:"Scientific Linux Security Update : postgresql on SL6.x, SL7.x i386/x86_64 (20150629)");
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
"A double-free flaw was found in the connection handling. An
unauthenticated attacker could exploit this flaw to crash the
PostgreSQL back end by disconnecting at approximately the same time as
the authentication time out is triggered. (CVE-2015-3165)

It was discovered that PostgreSQL did not properly check the return
values of certain standard library functions. If the system is in a
state that would cause the standard library functions to fail, for
example memory exhaustion, an authenticated user could exploit this
flaw to disclose partial memory contents or cause the GSSAPI
authentication to use an incorrect keytab file. (CVE-2015-3166)

It was discovered that the pgcrypto module could return different
error messages when decrypting certain data with an incorrect key.
This can help an authenticated user to launch a possible cryptographic
attack, although no suitable attack is currently known.
(CVE-2015-3167)

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1506&L=scientific-linux-errata&F=&S=&P=15210
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d8f6e1d"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/06");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"postgresql-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-contrib-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-debuginfo-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-devel-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-docs-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-libs-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plperl-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plpython-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-pltcl-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-server-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-test-8.4.20-3.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-contrib-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-debuginfo-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-devel-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-docs-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-libs-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-plperl-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-plpython-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-pltcl-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-server-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-test-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-upgrade-9.2.13-1.el7_1")) flag++;


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
