#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0474 and 
# CentOS Errata and Security Advisory 2009:0474 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38903);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0798");
  script_bugtraq_id(34692);
  script_xref(name:"RHSA", value:"2009:0474");

  script_name(english:"CentOS 3 / 4 / 5 : acpid (CESA-2009:0474)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated acpid package that fixes one security issue is now
available for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

acpid is a daemon that dispatches ACPI (Advanced Configuration and
Power Interface) events to user-space programs.

Anthony de Almeida Lopes of Outpost24 AB reported a denial of service
flaw in the acpid daemon's error handling. If an attacker could
exhaust the sockets open to acpid, the daemon would enter an infinite
loop, consuming most CPU resources and preventing acpid from
communicating with legitimate processes. (CVE-2009-0798)

Users are advised to upgrade to this updated package, which contains a
backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015846.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?968fdae6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015859.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d7730d6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4af514d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015873.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e2abf06"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015874.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f54063c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015926.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?566ba839"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015927.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24f189da"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected acpid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:acpid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/26");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"acpid-1.0.2-4")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"acpid-1.0.2-4")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"acpid-1.0.3-2.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"acpid-1.0.3-2.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"acpid-1.0.3-2.el4_7.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"acpid-1.0.4-7.el5_3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acpid");
}
