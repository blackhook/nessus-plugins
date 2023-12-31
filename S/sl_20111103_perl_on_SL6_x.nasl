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
  script_id(61169);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-2939", "CVE-2011-3597");

  script_name(english:"Scientific Linux Security Update : perl on SL6.x i386/x86_64");
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
"Perl is a high-level programming language commonly used for system
administration utilities and web programming.

A heap-based buffer overflow flaw was found in the way Perl decoded
Unicode strings. An attacker could create a malicious Unicode string
that, when decoded by a Perl program, would cause the program to crash
or, potentially, execute arbitrary code with the permissions of the
user running the program. (CVE-2011-2939)

It was found that the 'new' constructor of the Digest module used its
argument as part of the string expression passed to the eval()
function. An attacker could possibly use this flaw to execute
arbitrary Perl code with the privileges of a Perl program that uses
untrusted input as an argument to the constructor. (CVE-2011-3597)

All Perl users should upgrade to these updated packages, which contain
backported patches to correct these issues. All running Perl programs
must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1111&L=scientific-linux-errata&T=0&P=481
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c863db1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"perl-5.10.1-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Archive-Extract-0.38-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Archive-Tar-1.58-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-CGI-3.51-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-CPAN-1.9402-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-CPANPLUS-0.88-119.el6_1.1")) flag++;
# nb: see RHBA-2012-0843
#if (rpm_check(release:"SL6", reference:"perl-Compress-Raw-Zlib-2.023-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Compress-Zlib-2.020-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Digest-SHA-5.47-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-ExtUtils-CBuilder-0.27-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-ExtUtils-Embed-1.28-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-ExtUtils-MakeMaker-6.55-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-ExtUtils-ParseXS-2.2003.0-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-File-Fetch-0.26-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-IO-Compress-Base-2.020-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-IO-Compress-Zlib-2.020-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-IO-Zlib-1.09-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-IPC-Cmd-0.56-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Locale-Maketext-Simple-0.18-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Log-Message-0.02-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Log-Message-Simple-0.04-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Module-Build-0.3500-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Module-CoreList-2.18-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Module-Load-0.16-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Module-Load-Conditional-0.30-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Module-Loaded-0.02-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Module-Pluggable-3.90-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Object-Accessor-0.34-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Package-Constants-0.02-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Params-Check-0.26-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Parse-CPAN-Meta-1.40-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Pod-Escapes-1.04-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Pod-Simple-3.13-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Term-UI-0.20-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Test-Harness-3.17-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Test-Simple-0.92-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Time-HiRes-1.9721-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Time-Piece-1.15-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-core-5.10.1-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-debuginfo-5.10.1-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-devel-5.10.1-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-libs-5.10.1-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-parent-0.221-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-suidperl-5.10.1-119.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-version-0.77-119.el6_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
