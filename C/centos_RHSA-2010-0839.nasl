#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0839 and 
# CentOS Errata and Security Advisory 2010:0839 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50807);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-3066", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3086", "CVE-2010-3477");
  script_bugtraq_id(42529, 43022, 43353, 44754);
  script_xref(name:"RHSA", value:"2010:0839");

  script_name(english:"CentOS 5 : kernel (CESA-2010:0839)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A NULL pointer dereference flaw was found in the io_submit_one()
function in the Linux kernel asynchronous I/O implementation. A local,
unprivileged user could use this flaw to cause a denial of service.
(CVE-2010-3066, Moderate)

* A flaw was found in the xfs_ioc_fsgetxattr() function in the Linux
kernel XFS file system implementation. A data structure in
xfs_ioc_fsgetxattr() was not initialized properly before being copied
to user-space. A local, unprivileged user could use this flaw to cause
an information leak. (CVE-2010-3078, Moderate)

* The exception fixup code for the __futex_atomic_op1,
__futex_atomic_op2, and futex_atomic_cmpxchg_inatomic() macros
replaced the LOCK prefix with a NOP instruction. A local, unprivileged
user could use this flaw to cause a denial of service. (CVE-2010-3086,
Moderate)

* A flaw was found in the tcf_act_police_dump() function in the Linux
kernel network traffic policing implementation. A data structure in
tcf_act_police_dump() was not initialized properly before being copied
to user-space. A local, unprivileged user could use this flaw to cause
an information leak. (CVE-2010-3477, Moderate)

* A missing upper bound integer check was found in the sys_io_submit()
function in the Linux kernel asynchronous I/O implementation. A local,
unprivileged user could use this flaw to cause an information leak.
(CVE-2010-3067, Low)

Red Hat would like to thank Tavis Ormandy for reporting CVE-2010-3066,
CVE-2010-3086, and CVE-2010-3067, and Dan Rosenberg for reporting
CVE-2010-3078.

This update also fixes several bugs. Documentation for these bug fixes
will be available shortly from the Technical Notes document linked to
in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-November/017159.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30dadedf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-November/017160.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4bafbeb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/24");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-194.26.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-devel / kernel-debug / etc");
}
