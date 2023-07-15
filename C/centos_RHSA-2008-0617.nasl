#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0617 and 
# CentOS Errata and Security Advisory 2008:0617 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37794);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-2953", "CVE-2008-2712", "CVE-2008-3432", "CVE-2008-4101");
  script_xref(name:"RHSA", value:"2008:0617");

  script_name(english:"CentOS 3 / 4 : vim (CESA-2008:0617)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated vim packages that fix various security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Vim (Visual editor IMproved) is an updated and improved version of the
vi editor.

Several input sanitization flaws were found in Vim's keyword and tag
handling. If Vim looked up a document's maliciously crafted tag or
keyword, it was possible to execute arbitrary code as the user running
Vim. (CVE-2008-4101)

A heap-based overflow flaw was discovered in Vim's expansion of file
name patterns with shell wildcards. An attacker could create a
specially crafted file or directory name that, when opened by Vim,
caused the application to crash or, possibly, execute arbitrary code.
(CVE-2008-3432)

Several input sanitization flaws were found in various Vim system
functions. If a user opened a specially crafted file, it was possible
to execute arbitrary code as the user running Vim. (CVE-2008-2712)

Ulf Harnhammar, of Secunia Research, discovered a format string flaw
in Vim's help tag processor. If a user was tricked into executing the
'helptags' command on malicious data, arbitrary code could be executed
with the permissions of the user running Vim. (CVE-2007-2953)

All Vim users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015438.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc54fc6a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015439.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?367a1c9a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015440.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbfb5dee"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015442.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4a2cdf8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015457.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec3f54e1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015458.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22256de6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"vim-X11-6.3.046-0.30E.11")) flag++;
if (rpm_check(release:"CentOS-3", reference:"vim-common-6.3.046-0.30E.11")) flag++;
if (rpm_check(release:"CentOS-3", reference:"vim-enhanced-6.3.046-0.30E.11")) flag++;
if (rpm_check(release:"CentOS-3", reference:"vim-minimal-6.3.046-0.30E.11")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"vim-X11-6.3.046-1.el4_7.5z")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"vim-X11-6.3.046-1.c4.5z")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"vim-X11-6.3.046-1.el4_7.5z")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"vim-common-6.3.046-1.el4_7.5z")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"vim-common-6.3.046-1.c4.5z")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"vim-common-6.3.046-1.el4_7.5z")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"vim-enhanced-6.3.046-1.el4_7.5z")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"vim-enhanced-6.3.046-1.c4.5z")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"vim-enhanced-6.3.046-1.el4_7.5z")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"vim-minimal-6.3.046-1.el4_7.5z")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"vim-minimal-6.3.046-1.c4.5z")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"vim-minimal-6.3.046-1.el4_7.5z")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-X11 / vim-common / vim-enhanced / vim-minimal");
}
