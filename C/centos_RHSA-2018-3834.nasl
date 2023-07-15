#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3834 and 
# CentOS Errata and Security Advisory 2018:3834 respectively.
#

include("compat.inc");

if (description)
{
  script_id(119754);
  script_version("1.9");
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

  script_name(english:"CentOS 7 : ghostscript (CESA-2018:3834)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ghostscript is now available for Red Hat Enterprise
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
  # https://lists.centos.org/pipermail/centos-announce/2018-December/023134.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bae6b81");
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19409");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-cups-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-devel-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-doc-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-gtk-9.07-31.el7_6.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-cups / ghostscript-devel / etc");
}
