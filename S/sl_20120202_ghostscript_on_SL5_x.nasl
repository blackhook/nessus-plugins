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
  script_id(61236);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-3743", "CVE-2010-2055", "CVE-2010-4054", "CVE-2010-4820");

  script_name(english:"Scientific Linux Security Update : ghostscript on SL5.x, SL6.x i386/x86_64 (20120202)");
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
"Ghostscript is a set of software that provides a PostScript
interpreter, a set of C procedures (the Ghostscript library, which
implements the graphics capabilities in the PostScript language) and
an interpreter for Portable Document Format (PDF) files.

An integer overflow flaw was found in Ghostscript's TrueType bytecode
interpreter. An attacker could create a specially crafted PostScript
or PDF file that, when interpreted, could cause Ghostscript to crash
or, potentially, execute arbitrary code. (CVE-2009-3743)

It was found that Ghostscript always tried to read Ghostscript system
initialization files from the current working directory before
checking other directories, even if a search path that did not contain
the current working directory was specified with the '-I' option, or
the '-P-' option was used (to prevent the current working directory
being searched first). If a user ran Ghostscript in an
attacker-controlled directory containing a system initialization file,
it could cause Ghostscript to execute arbitrary PostScript code.
(CVE-2010-2055)

Ghostscript included the current working directory in its library
search path by default. If a user ran Ghostscript without the '-P-'
option in an attacker-controlled directory containing a specially
crafted PostScript library file, it could cause Ghostscript to execute
arbitrary PostScript code. With this update, Ghostscript no longer
searches the current working directory for library files by default.
(CVE-2010-4820)

Note: The fix for CVE-2010-4820 could possibly break existing
configurations. To use the previous, vulnerable behavior, run
Ghostscript with the '-P' option (to always search the current working
directory first).

A flaw was found in the way Ghostscript interpreted PostScript Type 1
and PostScript Type 2 font files. An attacker could create a specially
crafted PostScript Type 1 or PostScript Type 2 font file that, when
interpreted, could cause Ghostscript to crash or, potentially, execute
arbitrary code. (CVE-2010-4054)

Users of Ghostscript are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=784
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a89e1985"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/02");
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
if (rpm_check(release:"SL5", reference:"ghostscript-8.70-6.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"ghostscript-debuginfo-8.70-6.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"ghostscript-devel-8.70-6.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"ghostscript-gtk-8.70-6.el5_7.6")) flag++;

if (rpm_check(release:"SL6", reference:"ghostscript-8.70-11.el6_2.6")) flag++;
if (rpm_check(release:"SL6", reference:"ghostscript-debuginfo-8.70-11.el6_2.6")) flag++;
if (rpm_check(release:"SL6", reference:"ghostscript-devel-8.70-11.el6_2.6")) flag++;
if (rpm_check(release:"SL6", reference:"ghostscript-doc-8.70-11.el6_2.6")) flag++;
if (rpm_check(release:"SL6", reference:"ghostscript-gtk-8.70-11.el6_2.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-debuginfo / ghostscript-devel / etc");
}
