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
  script_id(63605);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-4772", "CVE-2007-6067");

  script_name(english:"Scientific Linux Security Update : tcl on SL5.x i386/x86_64 (20130108)");
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
"Two denial of service flaws were found in the Tcl regular expression
handling engine. If Tcl or an application using Tcl processed a
specially crafted regular expression, it would lead to excessive CPU
and memory consumption. (CVE-2007-4772, CVE-2007-6067)

This update also fixes the following bug :

  - Due to a suboptimal implementation of threading in the
    current version of the Tcl language interpreter, an
    attempt to use threads in combination with fork in a Tcl
    script could cause the script to stop responding. At the
    moment, it is not possible to rewrite the source code or
    drop support for threading entirely. Consequent to this,
    this update provides a version of Tcl without threading
    support in addition to the standard version with this
    support. Users who need to use fork in their Tcl scripts
    and do not require threading can now switch to the
    version without threading support by using the
    alternatives command."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=845
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66ed624f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tcl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tcl-html");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"tcl-8.4.13-6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"tcl-debuginfo-8.4.13-6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"tcl-devel-8.4.13-6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"tcl-html-8.4.13-6.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcl / tcl-debuginfo / tcl-devel / tcl-html");
}
