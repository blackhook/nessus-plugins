#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:3760 and 
# Oracle Linux Security Advisory ELSA-2018-3760 respectively.
#

include("compat.inc");

if (description)
{
  script_id(119328);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/27 13:00:39");

  script_cve_id("CVE-2018-16509");
  script_xref(name:"RHSA", value:"2018:3760");

  script_name(english:"Oracle Linux 6 : ghostscript (ELSA-2018-3760)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:3760 :

An update for ghostscript is now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Ghostscript suite contains utilities for rendering PostScript and
PDF documents. Ghostscript translates PostScript code to common bitmap
formats so that the code can be displayed or printed.

Security Fix(es) :

* It was discovered that the ghostscript /invalidaccess checks fail
under certain conditions. An attacker could possibly exploit this to
bypass the -dSAFER protection and, for example, execute arbitrary
shell commands via a specially crafted PostScript document.
(CVE-2018-16509)

Red Hat would like to thank Tavis Ormandy (Google Project Zero) for
reporting this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-December/008315.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ghostscript Failed Restore Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"ghostscript-8.70-24.el6_10.2")) flag++;
if (rpm_check(release:"EL6", reference:"ghostscript-devel-8.70-24.el6_10.2")) flag++;
if (rpm_check(release:"EL6", reference:"ghostscript-doc-8.70-24.el6_10.2")) flag++;
if (rpm_check(release:"EL6", reference:"ghostscript-gtk-8.70-24.el6_10.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-devel / ghostscript-doc / ghostscript-gtk");
}
