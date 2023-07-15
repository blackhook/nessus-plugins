#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1233 and 
# CentOS Errata and Security Advisory 2009:1233 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40808);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-2692", "CVE-2009-2698");
  script_bugtraq_id(36038, 36108);
  script_xref(name:"RHSA", value:"2009:1233");

  script_name(english:"CentOS 3 : kernel (CESA-2009:1233)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues are now available
for Red Hat Enterprise Linux 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

These updated packages fix the following security issues :

* a flaw was found in the SOCKOPS_WRAP macro in the Linux kernel. This
macro did not initialize the sendpage operation in the proto_ops
structure correctly. A local, unprivileged user could use this flaw to
cause a local denial of service or escalate their privileges.
(CVE-2009-2692, Important)

* a flaw was found in the udp_sendmsg() implementation in the Linux
kernel when using the MSG_MORE flag on UDP sockets. A local,
unprivileged user could use this flaw to cause a local denial of
service or escalate their privileges. (CVE-2009-2698, Important)

Red Hat would like to thank Tavis Ormandy and Julien Tinnes of the
Google Security Team for responsibly reporting these flaws.

All Red Hat Enterprise Linux 3 users should upgrade to these updated
packages, which contain backported patches to resolve these issues.
The system must be rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-August/016117.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9b59a5a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-August/016118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d40178c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-unsupported");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/31");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-BOOT-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-doc-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-doc-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-source-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-source-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-unsupported-2.4.21-60.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-unsupported-2.4.21-60.EL")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-doc / kernel-hugemem / etc");
}
