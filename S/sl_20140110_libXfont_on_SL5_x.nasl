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
  script_id(71910);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-6462");

  script_name(english:"Scientific Linux Security Update : libXfont on SL5.x, SL6.x i386/x86_64 (20140110)");
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
"A stack-based buffer overflow flaw was found in the way the libXfont
library parsed Glyph Bitmap Distribution Format (BDF) fonts. A
malicious, local user could exploit this issue to potentially execute
arbitrary code with the privileges of the X.Org server.
(CVE-2013-6462)

All running X.Org server instances must be restarted for the update to
take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1401&L=scientific-linux-errata&T=0&P=437
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a85a9f3a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libXfont, libXfont-debuginfo and / or
libXfont-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"libXfont-1.2.2-1.0.5.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"libXfont-debuginfo-1.2.2-1.0.5.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"libXfont-devel-1.2.2-1.0.5.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"libXfont-1.4.5-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"libXfont-debuginfo-1.4.5-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"libXfont-devel-1.4.5-3.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libXfont / libXfont-debuginfo / libXfont-devel");
}
