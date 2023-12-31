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
  script_id(82251);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-9273");

  script_name(english:"Scientific Linux Security Update : hivex on SL7.x x86_64 (20150305)");
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
"It was found that hivex attempted to read beyond its allocated buffer
when reading a hive file with a very small size or with a truncated or
improperly formatted content. An attacker able to supply a specially
crafted hive file to an application using the hivex library could
possibly use this flaw to execute arbitrary code with the privileges
of the user running that application. (CVE-2014-9273)

The hivex package has been upgraded to upstream version 1.3.10, which
provides a number of bug fixes and enhancements over the previous
version.

This update also fixes the following bugs :

  - Due to an error in the hivex_value_data_cell_offset()
    function, the hivex utility could, in some cases, print
    an 'Argument list is too long' message and terminate
    unexpectedly when processing hive files from the Windows
    Registry. This update fixes the underlying code and
    hivex now processes hive files as expected.

  - A typographical error in the Win::Hivex.3pm manual page
    has been corrected."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=1920
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7daac751"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"hivex-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"hivex-debuginfo-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"hivex-devel-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-hivex-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-hivex-devel-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-hivex-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-hivex-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-hivex-1.3.10-5.7.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hivex / hivex-debuginfo / hivex-devel / ocaml-hivex / etc");
}
