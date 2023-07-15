#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1270 and 
# CentOS Errata and Security Advisory 2013:1270 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69998);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-4288");
  script_bugtraq_id(62511);
  script_xref(name:"RHSA", value:"2013:1270");

  script_name(english:"CentOS 6 : polkit (CESA-2013:1270)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated polkit packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

PolicyKit is a toolkit for defining and handling authorizations.

A race condition was found in the way the PolicyKit pkcheck utility
checked process authorization when the process was specified by its
process ID via the --process option. A local user could use this flaw
to bypass intended PolicyKit authorizations and escalate their
privileges. (CVE-2013-4288)

Note: Applications that invoke pkcheck with the --process option need
to be modified to use the pid,pid-start-time,uid argument for that
option, to allow pkcheck to check process authorization correctly.

Red Hat would like to thank Sebastian Krahmer of the SUSE Security
Team for reporting this issue.

All polkit users should upgrade to these updated packages, which
contain a backported patch to correct this issue. The system must be
rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-September/019949.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f43117d1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected polkit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4288");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:polkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:polkit-desktop-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:polkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:polkit-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"polkit-0.96-5.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"polkit-desktop-policy-0.96-5.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"polkit-devel-0.96-5.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"polkit-docs-0.96-5.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "polkit / polkit-desktop-policy / polkit-devel / polkit-docs");
}
