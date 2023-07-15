#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(121326);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-18311");

  script_name(english:"Scientific Linux Security Update : perl on SL7.x x86_64 (20190122)");
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
"Security Fix(es) :

  - perl: Integer overflow leading to buffer overflow in
    Perl_my_setenv() (CVE-2018-18311)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1901&L=SCIENTIFIC-LINUX-ERRATA&P=2498
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f41b84c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-ExtUtils-Install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Module-CoreList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Object-Accessor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Package-Constants");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-tests");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-5.16.3-294.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"perl-CPAN-1.9800-294.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"perl-ExtUtils-CBuilder-0.28.2.6-294.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"perl-ExtUtils-Embed-1.30-294.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"perl-ExtUtils-Install-1.58-294.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"perl-IO-Zlib-1.10-294.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"perl-Locale-Maketext-Simple-0.21-294.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"perl-Module-CoreList-2.76.02-294.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"perl-Module-Loaded-0.08-294.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"perl-Object-Accessor-0.42-294.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"perl-Package-Constants-0.02-294.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"perl-Pod-Escapes-1.04-294.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-Time-Piece-1.20.1-294.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-core-5.16.3-294.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-debuginfo-5.16.3-294.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-devel-5.16.3-294.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-libs-5.16.3-294.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-macros-5.16.3-294.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-tests-5.16.3-294.el7_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-CPAN / perl-ExtUtils-CBuilder / perl-ExtUtils-Embed / etc");
}
