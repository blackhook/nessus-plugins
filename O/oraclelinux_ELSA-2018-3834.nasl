#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:3834 and 
# Oracle Linux Security Advisory ELSA-2018-3834 respectively.
#

include("compat.inc");

if (description)
{
  script_id(119757);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/21");

  script_cve_id(
    "CVE-2018-15911",
    "CVE-2018-16541",
    "CVE-2018-16802",
    "CVE-2018-17183",
    "CVE-2018-17961",
    "CVE-2018-18073",
    "CVE-2018-18284",
    "CVE-2018-19134",
    "CVE-2018-19409"
  );
  script_xref(name:"RHSA", value:"2018:3834");
  script_xref(name:"IAVB", value:"2019-B-0081-S");

  script_name(english:"Oracle Linux 7 : ghostscript (ELSA-2018-3834)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:3834 :

An update for ghostscript is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Ghostscript suite contains utilities for rendering PostScript and
PDF documents. Ghostscript translates PostScript code to common bitmap
formats so that the code can be displayed or printed.

Security Fix(es) :

* ghostscript: Incorrect free logic in pagedevice replacement (699664)
(CVE-2018-16541)

* ghostscript: Incorrect 'restoration of privilege' checking when
running out of stack during exception handling (CVE-2018-16802)

* ghostscript: User-writable error exception table (CVE-2018-17183)

* ghostscript: Saved execution stacks can leak operator arrays
(incomplete fix for CVE-2018-17183) (CVE-2018-17961)

* ghostscript: Saved execution stacks can leak operator arrays
(CVE-2018-18073)

* ghostscript: 1Policy operator allows a sandbox protection bypass
(CVE-2018-18284)

* ghostscript: Type confusion in setpattern (700141) (CVE-2018-19134)

* ghostscript: Improperly implemented security check in zsetdevice
function in psi/zdevice.c (CVE-2018-19409)

* ghostscript: Uninitialized memory access in the aesdecode operator
(699665) (CVE-2018-15911)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Tavis Ormandy (Google Project Zero) for
reporting CVE-2018-16541.

Bug Fix(es) :

* It has been found that ghostscript-9.07-31.el7_6.1 introduced
regression during the handling of shading objects, causing a 'Dropping
incorrect smooth shading object' warning. With this update, the
regression has been fixed and the described problem no longer occurs.
(BZ#1657822)"
  );
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2018-December/008339.html");
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ghostscript-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ghostscript-cups-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ghostscript-devel-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ghostscript-doc-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ghostscript-gtk-9.07-31.el7_6.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-cups / ghostscript-devel / etc");
}
