#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1535 and 
# CentOS Errata and Security Advisory 2009:1535 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42309);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-2703", "CVE-2009-3083", "CVE-2009-3615");
  script_bugtraq_id(36277);
  script_xref(name:"RHSA", value:"2009:1535");

  script_name(english:"CentOS 3 : pidgin (CESA-2009:1535)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated pidgin package that fixes several security issues is now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

An invalid pointer dereference bug was found in the way the Pidgin
OSCAR protocol implementation processed lists of contacts. A remote
attacker could send a specially crafted contact list to a user running
Pidgin, causing Pidgin to crash. (CVE-2009-3615)

A NULL pointer dereference flaw was found in the way the Pidgin IRC
protocol plug-in handles IRC topics. A malicious IRC server could send
a specially crafted IRC TOPIC message, which once received by Pidgin,
would lead to a denial of service (Pidgin crash). (CVE-2009-2703)

A NULL pointer dereference flaw was found in the way the Pidgin MSN
protocol plug-in handles improper MSNSLP invitations. A remote
attacker could send a specially crafted MSNSLP invitation request,
which once accepted by a valid Pidgin user, would lead to a denial of
service (Pidgin crash). (CVE-2009-3083)

All Pidgin users should upgrade to this updated package, which
contains backported patches to resolve these issues. Pidgin must be
restarted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016208.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5649c188"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016209.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a32cb83"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/30");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"pidgin-1.5.1-6.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"pidgin-1.5.1-6.el3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pidgin");
}
