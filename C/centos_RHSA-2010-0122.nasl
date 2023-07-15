#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0122 and 
# CentOS Errata and Security Advisory 2010:0122 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44949);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0426", "CVE-2010-0427");
  script_bugtraq_id(38362);
  script_xref(name:"RHSA", value:"2010:0122");

  script_name(english:"CentOS 5 : sudo (CESA-2010:0122)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sudo package that fixes two security issues is now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The sudo (superuser do) utility allows system administrators to give
certain users the ability to run commands as root.

A privilege escalation flaw was found in the way sudo handled the
sudoedit pseudo-command. If a local user were authorized by the
sudoers file to use this pseudo-command, they could possibly leverage
this flaw to execute arbitrary code with the privileges of the root
user. (CVE-2010-0426)

The sudo utility did not properly initialize supplementary groups when
the 'runas_default' option (in the sudoers file) was used. If a local
user were authorized by the sudoers file to perform their sudo
commands under the account specified with 'runas_default', they would
receive the root user's supplementary groups instead of those of the
intended target user, giving them unintended privileges.
(CVE-2010-0427)

Users of sudo should upgrade to this updated package, which contains
backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-March/016531.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8cc2ec24"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-March/016532.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c3bd296"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sudo package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"sudo-1.6.9p17-6.el5_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo");
}
