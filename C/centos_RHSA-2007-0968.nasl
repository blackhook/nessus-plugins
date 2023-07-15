#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0968 and 
# CentOS Errata and Security Advisory 2007:0968 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37507);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1660");
  script_xref(name:"RHSA", value:"2007:0968");

  script_name(english:"CentOS 4 : pcre (CESA-2007:0968)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pcre packages that correct two security flaws are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

PCRE is a Perl-compatible regular expression library.

Multiple flaws were found in the way pcre handles certain malformed
regular expressions. If an application linked against pcre, such as
Konqueror, parses a malicious regular expression, it may be possible
to run arbitrary code as the user running the application.
(CVE-2007-1660)

Users of pcre are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.

Red Hat would like to thank Tavis Ormandy and Will Drewry for properly
disclosing these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-November/014364.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de8a84b1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-November/014389.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a989bd3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-November/014390.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a93d05ee"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pcre packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcre-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/08");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pcre-4.5-4.el4_5.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"pcre-4.5-4.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pcre-4.5-4.el4_5.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pcre-devel-4.5-4.el4_5.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"pcre-devel-4.5-4.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pcre-devel-4.5-4.el4_5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcre / pcre-devel");
}
