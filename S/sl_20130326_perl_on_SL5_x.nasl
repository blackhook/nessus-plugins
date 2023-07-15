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
  script_id(65715);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-5195", "CVE-2012-5526", "CVE-2012-6329", "CVE-2013-1667");

  script_name(english:"Scientific Linux Security Update : perl on SL5.x, SL6.x i386/x86_64 (20130326)");
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
"A heap overflow flaw was found in Perl. If a Perl application allowed
user input to control the count argument of the string repeat
operator, an attacker could cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2012-5195)

A denial of service flaw was found in the way Perl's rehashing code
implementation, responsible for recalculation of hash keys and
redistribution of hash content, handled certain input. If an attacker
supplied specially crafted input to be used as hash keys by a Perl
application, it could cause excessive memory consumption.
(CVE-2013-1667)

It was found that the Perl CGI module, used to handle Common Gateway
Interface requests and responses, incorrectly sanitized the values for
Set-Cookie and P3P headers. If a Perl application using the CGI module
reused cookies values and accepted untrusted input from web browsers,
a remote attacker could use this flaw to alter member items of the
cookie or add new items. (CVE-2012-5526)

It was found that the Perl Locale::Maketext module, used to localize
Perl applications, did not properly handle backslashes or
fully-qualified method names. An attacker could possibly use this flaw
to execute arbitrary Perl code with the privileges of a Perl
application that uses untrusted Locale::Maketext templates.
(CVE-2012-6329)

All running Perl programs must be restarted for this update to take
effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=6026
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5976fb39"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"TWiki 5.1.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TWiki MAKETEXT Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Archive-Extract");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Archive-Tar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-CGI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-CPANPLUS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Compress-Raw-Bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Compress-Raw-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Compress-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Digest-SHA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-ExtUtils-MakeMaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-ExtUtils-ParseXS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-File-Fetch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-IO-Compress-Base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-IO-Compress-Bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-IO-Compress-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-IPC-Cmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Log-Message");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Log-Message-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Module-Build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Module-CoreList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Module-Load");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Module-Load-Conditional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Module-Pluggable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Object-Accessor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Package-Constants");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Params-Check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Parse-CPAN-Meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Pod-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Term-UI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Test-Harness");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Test-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Time-HiRes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-version");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/28");
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
if (rpm_check(release:"SL5", reference:"perl-5.8.8-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"perl-debuginfo-5.8.8-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"perl-suidperl-5.8.8-40.el5_9")) flag++;

if (rpm_check(release:"SL6", reference:"perl-5.10.1-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Archive-Extract-0.38-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Archive-Tar-1.58-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-CGI-3.51-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-CPAN-1.9402-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-CPANPLUS-0.88-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Compress-Raw-Bzip2-2.020-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Compress-Raw-Zlib-2.020-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Compress-Zlib-2.020-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Digest-SHA-5.47-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-ExtUtils-CBuilder-0.27-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-ExtUtils-Embed-1.28-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-ExtUtils-MakeMaker-6.55-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-ExtUtils-ParseXS-2.2003.0-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-File-Fetch-0.26-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-IO-Compress-Base-2.020-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-IO-Compress-Bzip2-2.020-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-IO-Compress-Zlib-2.020-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-IO-Zlib-1.09-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-IPC-Cmd-0.56-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Locale-Maketext-Simple-0.18-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Log-Message-0.02-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Log-Message-Simple-0.04-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Module-Build-0.3500-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Module-CoreList-2.18-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Module-Load-0.16-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Module-Load-Conditional-0.30-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Module-Loaded-0.02-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Module-Pluggable-3.90-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Object-Accessor-0.34-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Package-Constants-0.02-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Params-Check-0.26-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Parse-CPAN-Meta-1.40-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Pod-Escapes-1.04-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Pod-Simple-3.13-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Term-UI-0.20-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Test-Harness-3.17-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Test-Simple-0.92-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Time-HiRes-1.9721-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Time-Piece-1.15-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-core-5.10.1-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-debuginfo-5.10.1-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-devel-5.10.1-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-libs-5.10.1-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-parent-0.221-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-suidperl-5.10.1-130.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"perl-version-0.77-130.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-Archive-Extract / perl-Archive-Tar / perl-CGI / etc");
}
