#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0927 and 
# CentOS Errata and Security Advisory 2011:0927 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55609);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-4649", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-1044", "CVE-2011-1182", "CVE-2011-1573", "CVE-2011-1576", "CVE-2011-1593", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1776", "CVE-2011-1936", "CVE-2011-2022", "CVE-2011-2213", "CVE-2011-2492");
  script_bugtraq_id(46073, 46417, 46488, 46839, 47003, 47308, 47497, 47534, 47535, 47796, 47843, 48333, 48441, 48610);
  script_xref(name:"RHSA", value:"2011:0927");

  script_name(english:"CentOS 5 : kernel (CESA-2011:0927)");
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

* An integer overflow flaw in ib_uverbs_poll_cq() could allow a local,
unprivileged user to cause a denial of service or escalate their
privileges. (CVE-2010-4649, Important)

* A race condition in the way new InfiniBand connections were set up
could allow a remote user to cause a denial of service.
(CVE-2011-0695, Important)

* A flaw in the Stream Control Transmission Protocol (SCTP)
implementation could allow a remote attacker to cause a denial of
service if the sysctl 'net.sctp.addip_enable' variable was turned on
(it is off by default). (CVE-2011-1573, Important)

* Flaws in the AGPGART driver implementation when handling certain
IOCTL commands could allow a local, unprivileged user to cause a
denial of service or escalate their privileges. (CVE-2011-1745,
CVE-2011-2022, Important)

* An integer overflow flaw in agp_allocate_memory() could allow a
local, unprivileged user to cause a denial of service or escalate
their privileges. (CVE-2011-1746, Important)

* A flaw allowed napi_reuse_skb() to be called on VLAN (virtual LAN)
packets. An attacker on the local network could trigger this flaw by
sending specially crafted packets to a target system, possibly causing
a denial of service. (CVE-2011-1576, Moderate)

* An integer signedness error in next_pidmap() could allow a local,
unprivileged user to cause a denial of service. (CVE-2011-1593,
Moderate)

* A flaw in the way the Xen hypervisor implementation handled CPUID
instruction emulation during virtual machine exits could allow an
unprivileged guest user to crash a guest. This only affects systems
that have an Intel x86 processor with the Intel VT-x extension
enabled. (CVE-2011-1936, Moderate)

* A flaw in inet_diag_bc_audit() could allow a local, unprivileged
user to cause a denial of service (infinite loop). (CVE-2011-2213,
Moderate)

* A missing initialization flaw in the XFS file system implementation
could lead to an information leak. (CVE-2011-0711, Low)

* A flaw in ib_uverbs_poll_cq() could allow a local, unprivileged user
to cause an information leak. (CVE-2011-1044, Low)

* A missing validation check was found in the signals implementation.
A local, unprivileged user could use this flaw to send signals via the
sigqueueinfo system call, with the si_code set to SI_TKILL and with
spoofed process and user IDs, to other processes. Note: This flaw does
not allow existing permission checks to be bypassed; signals can only
be sent if your privileges allow you to already do so. (CVE-2011-1182,
Low)

* A heap overflow flaw in the EFI GUID Partition Table (GPT)
implementation could allow a local attacker to cause a denial of
service by mounting a disk containing specially crafted partition
tables. (CVE-2011-1776, Low)

* Structure padding in two structures in the Bluetooth implementation
was not initialized properly before being copied to user-space,
possibly allowing local, unprivileged users to leak kernel stack
memory to user-space. (CVE-2011-2492, Low)

Red Hat would like to thank Jens Kuehnel for reporting CVE-2011-0695;
Vasiliy Kulikov for reporting CVE-2011-1745, CVE-2011-2022, and
CVE-2011-1746; Ryan Sweat for reporting CVE-2011-1576; Robert Swiecki
for reporting CVE-2011-1593; Dan Rosenberg for reporting CVE-2011-2213
and CVE-2011-0711; Julien Tinnes of the Google Security Team for
reporting CVE-2011-1182; Timo Warns for reporting CVE-2011-1776; and
Marek Kroemeke and Filip Palian for reporting CVE-2011-2492.

Bug fix documentation will be available shortly from the Technical
Notes document linked to in the References.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs noted in
the Technical Notes. The system must be rebooted for this update to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-July/017646.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d65c9da"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-July/017647.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d98f161"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-238.19.1.el5")) flag++;


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
