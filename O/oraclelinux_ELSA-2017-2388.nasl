#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2388 and 
# Oracle Linux Security Advisory ELSA-2017-2388 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102343);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-1000083");
  script_xref(name:"RHSA", value:"2017:2388");

  script_name(english:"Oracle Linux 7 : evince (ELSA-2017-2388)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:2388 :

An update for evince is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The evince packages provide a simple multi-page document viewer for
Portable Document Format (PDF), PostScript (PS), Encapsulated
PostScript (EPS) files, and, with additional back-ends, also the
Device Independent File format (DVI) files.

Security Fix(es) :

* It was found that evince did not properly sanitize the command line
which is run to untar Comic Book Tar (CBT) files, thereby allowing
command injection. A specially crafted CBT file, when opened by evince
or evince-thumbnailer, could execute arbitrary commands in the context
of the evince program. (CVE-2017-1000083)

Red Hat would like to thank Felix Wilhelm (Google Security Team) for
reporting this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-August/007110.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evince packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Evince CBT File Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-dvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-nautilus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"evince-3.22.1-5.2.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"evince-browser-plugin-3.22.1-5.2.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"evince-devel-3.22.1-5.2.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"evince-dvi-3.22.1-5.2.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"evince-libs-3.22.1-5.2.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"evince-nautilus-3.22.1-5.2.el7_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evince / evince-browser-plugin / evince-devel / evince-dvi / etc");
}
