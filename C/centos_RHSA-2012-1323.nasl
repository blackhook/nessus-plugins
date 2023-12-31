#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1323 and 
# CentOS Errata and Security Advisory 2012:1323 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62431);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-2319", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-3510");
  script_bugtraq_id(53401, 54702, 54763, 55144);
  script_xref(name:"RHSA", value:"2012:1323");

  script_name(english:"CentOS 5 : kernel (CESA-2012:1323)");
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
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw was found in the way socket buffers (skb) requiring TSO (TCP
segment offloading) were handled by the sfc driver. If the skb did not
fit within the minimum-size of the transmission queue, the network
card could repeatedly reset itself. A remote attacker could use this
flaw to cause a denial of service. (CVE-2012-3412, Important)

* A use-after-free flaw was found in the xacct_add_tsk() function in
the Linux kernel's taskstats subsystem. A local, unprivileged user
could use this flaw to cause an information leak or a denial of
service. (CVE-2012-3510, Moderate)

* A buffer overflow flaw was found in the hfs_bnode_read() function in
the HFS Plus (HFS+) file system implementation in the Linux kernel. A
local user able to mount a specially crafted HFS+ file system image
could use this flaw to cause a denial of service or escalate their
privileges. (CVE-2012-2319, Low)

* A flaw was found in the way the msg_namelen variable in the
rds_recvmsg() function of the Linux kernel's Reliable Datagram Sockets
(RDS) protocol implementation was initialized. A local, unprivileged
user could use this flaw to leak kernel stack memory to user-space.
(CVE-2012-3430, Low)

Red Hat would like to thank Ben Hutchings of Solarflare (tm) for
reporting CVE-2012-3412, and Alexander Peslyak for reporting
CVE-2012-3510. The CVE-2012-3430 issue was discovered by the Red Hat
InfiniBand team.

This update also fixes the following bugs :

* The cpuid_whitelist() function, masking the Enhanced Intel SpeedStep
(EST) flag from all guests, prevented the 'cpuspeed' service from
working in the privileged Xen domain (dom0). CPU scaling was therefore
not possible. With this update, cpuid_whitelist() is aware whether the
domain executing CPUID is privileged or not, and enables the EST flag
for dom0. (BZ#846125)

* If a delayed-allocation write was performed before quota was
enabled, the kernel displayed the following warning message :

WARNING: at fs/quota/dquot.c:988 dquot_claim_space+0x77/0x112()

This was because information about the delayed allocation was not
recorded in the quota structure. With this update, writes prior to
enabling quota are properly accounted for, and the message is not
displayed. (BZ#847326)

* In Red Hat Enterprise Linux 5.9, the DSCP (Differentiated Services
Code Point) netfilter module now supports mangling of the DSCP field.
(BZ#847327)

* Some subsystems clear the TIF_SIGPENDING flag during error handling
in fork() paths. Previously, if the flag was cleared, the
ERESTARTNOINTR error code could be returned. The underlying source
code has been modified so that the error code is no longer returned.
(BZ#847359)

* An unnecessary check for the RXCW.CW bit could cause the Intel
e1000e NIC (Network Interface Controller) to not work properly. The
check has been removed so that the Intel e1000e NIC works as expected.
(BZ#852448)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-October/018911.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7b85c38"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3412");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-308.16.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-devel / kernel-debug / etc");
}
