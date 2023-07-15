#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1483. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100893);
  script_version("3.16");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-1000364");
  script_xref(name:"RHSA", value:"2017:1483");
  script_xref(name:"IAVB", value:"2017-B-0075");

  script_name(english:"RHEL 5 : kernel (RHSA-2017:1483) (Stack Clash)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 5.9
Long Life.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* A flaw was found in the way memory was being allocated on the stack
for user space binaries. If heap (or different memory region) and
stack memory regions were adjacent to each other, an attacker could
use this flaw to jump over the stack guard gap, cause controlled
memory corruption on process stack or the adjacent memory region, and
thus increase their privileges on the system. This is a kernel-side
mitigation which increases the stack guard gap size from one page to 1
MiB to make successful exploitation of this issue more difficult.
(CVE-2017-1000364, Important)

Red Hat would like to thank Qualys Research Labs for reporting this
issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-1000364.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/stackguard"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-1483.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'rsh_stack_clash_priv_esc.rb');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5\.9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.9", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1483";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-PAE-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-PAE-debuginfo-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debug-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debug-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debug-devel-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debuginfo-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debuginfo-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debuginfo-common-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debuginfo-common-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-devel-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-devel-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", reference:"kernel-doc-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"kernel-headers-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-headers-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-xen-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-xen-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-xen-debuginfo-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-xen-debuginfo-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-xen-devel-2.6.18-348.33.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-348.33.2.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-debuginfo / kernel-PAE-devel / etc");
  }
}
