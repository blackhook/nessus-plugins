#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1223. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40766);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-2692", "CVE-2009-2698");
  script_bugtraq_id(36038);
  script_xref(name:"RHSA", value:"2009:1223");

  script_name(english:"RHEL 4 : kernel (RHSA-2009:1223)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues are now available
for Red Hat Enterprise Linux 4.

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

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-2692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-2698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2009:1223"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");
include("ksplice.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2009-2692", "CVE-2009-2698");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2009:1223");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1223";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL4", reference:"kernel-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kernel-devel-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kernel-doc-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-devel-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-devel-2.6.9-89.0.9.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-89.0.9.EL")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-doc / kernel-hugemem / etc");
  }
}
