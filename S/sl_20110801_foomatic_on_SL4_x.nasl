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
  script_id(61103);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-2697");

  script_name(english:"Scientific Linux Security Update : foomatic on SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Foomatic is a comprehensive, spooler-independent database of printers,
printer drivers, and driver descriptions. The package also includes
spooler-independent command line interfaces to manipulate queues and
to print files and manipulate print jobs. foomatic-rip is a print
filter written in Perl.

An input sanitization flaw was found in the foomatic-rip print filter.
An attacker could submit a print job with the username, title, or job
options set to appear as a command line option that caused the filter
to use a specified PostScript printer description (PPD) file, rather
than the administrator-set one. This could lead to arbitrary code
execution with the privileges of the 'lp' user. (CVE-2011-2697)

All foomatic users should upgrade to this updated package, which
contains a backported patch to resolve this issue."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1108&L=scientific-linux-errata&T=0&P=298
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07801b88"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected foomatic package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/01");
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
if (rpm_check(release:"SL4", reference:"foomatic-3.0.2-3.2.el4")) flag++;

if (rpm_check(release:"SL5", reference:"foomatic-3.0.2-38.3.el5_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
