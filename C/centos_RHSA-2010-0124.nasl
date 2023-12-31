#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0124 and 
# CentOS Errata and Security Advisory 2010:0124 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44968);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-4273", "CVE-2010-0411");
  script_xref(name:"RHSA", value:"2010:0124");

  script_name(english:"CentOS 5 : systemtap (CESA-2010:0124)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated systemtap packages that fix two security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

SystemTap is an instrumentation system for systems running the Linux
kernel, version 2.6. Developers can write scripts to collect data on
the operation of the system.

A flaw was found in the SystemTap compile server, stap-server, an
optional component of SystemTap. This server did not adequately
sanitize input provided by the stap-client program, which may allow a
remote user to execute arbitrary shell code with the privileges of the
compile server process, which could possibly be running as the root
user. (CVE-2009-4273)

Note: stap-server is not run by default. It must be started by a user
or administrator.

A buffer overflow flaw was found in SystemTap's tapset __get_argv()
function. If a privileged user ran a SystemTap script that called this
function, a local, unprivileged user could, while that script is still
running, trigger this flaw and cause memory corruption by running a
command with a large argument list, which may lead to a system crash
or, potentially, arbitrary code execution with root privileges.
(CVE-2010-0411)

Note: SystemTap scripts that call __get_argv(), being a privileged
function, can only be executed by the root user or users in the
stapdev group. As well, if such a script was compiled and installed by
root, users in the stapusr group would also be able to execute it.

SystemTap users should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-March/016540.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3db5478"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-March/016541.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e093070f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemtap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-initscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-sdt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/04");
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
if (rpm_check(release:"CentOS-5", reference:"systemtap-0.9.7-5.el5_4.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-client-0.9.7-5.el5_4.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-initscript-0.9.7-5.el5_4.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-runtime-0.9.7-5.el5_4.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-sdt-devel-0.9.7-5.el5_4.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-server-0.9.7-5.el5_4.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-testsuite-0.9.7-5.el5_4.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemtap / systemtap-client / systemtap-initscript / etc");
}
