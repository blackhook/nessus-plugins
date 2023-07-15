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
  script_id(60800);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-1168", "CVE-2010-1447");

  script_name(english:"Scientific Linux Security Update : perl on SL3.x, SL4.x i386/x86_64");
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
administration utilities and web programming. The Safe extension
module allows users to compile and execute Perl code in restricted
compartments.

The Safe module did not properly restrict the code of implicitly
called methods (such as DESTROY and AUTOLOAD) on implicitly blessed
objects returned as a result of unsafe code evaluation. These methods
could have been executed unrestricted by Safe when such objects were
accessed or destroyed. A specially crafted Perl script executed inside
of a Safe compartment could use this flaw to bypass intended Safe
module restrictions. (CVE-2010-1168)

The Safe module did not properly restrict code compiled in a Safe
compartment and executed out of the compartment via a subroutine
reference returned as a result of unsafe code evaluation. A specially
crafted Perl script executed inside of a Safe compartment could use
this flaw to bypass intended Safe module restrictions, if the returned
subroutine reference was called from outside of the compartment.
(CVE-2010-1447)

These packages upgrade the Safe extension module to version 2.27.
Refer to the Safe module's Changes file at the following link for a
full list of changes.
http://cpansearch.perl.org/src/RGARCIA/Safe-2.27/Changes

All applications using the Safe extension module must be restarted for
this update to take effect."
  );
  # http://cpansearch.perl.org/src/RGARCIA/Safe-2.27/Changes
  script_set_attribute(
    attribute:"see_also",
    value:"https://fastapi.metacpan.org/source/RGARCIA/Safe-2.27/Changes"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1006&L=scientific-linux-errata&T=0&P=519
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5715f08a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
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
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL3", reference:"perl-5.8.0-101.EL3")) flag++;
if (rpm_check(release:"SL3", reference:"perl-CGI-2.89-101.EL3")) flag++;
if (rpm_check(release:"SL3", reference:"perl-CPAN-1.61-101.EL3")) flag++;
if (rpm_check(release:"SL3", reference:"perl-DB_File-1.806-101.EL3")) flag++;
if (rpm_check(release:"SL3", reference:"perl-suidperl-5.8.0-101.EL3")) flag++;

if (rpm_check(release:"SL4", reference:"perl-5.8.5-53.el4")) flag++;
if (rpm_check(release:"SL4", reference:"perl-suidperl-5.8.5-53.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
