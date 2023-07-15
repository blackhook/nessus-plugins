#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1540 and 
# CentOS Errata and Security Advisory 2012:1540 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63171);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-2372", "CVE-2012-3552", "CVE-2012-4508", "CVE-2012-4535", "CVE-2012-4537", "CVE-2012-5513");
  script_bugtraq_id(54062, 55359, 56238, 56498, 56797);
  script_xref(name:"RHSA", value:"2012:1540");

  script_name(english:"CentOS 5 : kernel (CESA-2012:1540)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated kernel packages that fix multiple security issues, two bugs,
and add two enhancements are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages contain the Linux kernel.

Security fixes :

* A race condition in the way asynchronous I/O and fallocate()
interacted when using ext4 could allow a local, unprivileged user to
obtain random data from a deleted file. (CVE-2012-4508, Important)

* A flaw in the way the Xen hypervisor implementation range checked
guest provided addresses in the XENMEM_exchange hypercall could allow
a malicious, para-virtualized guest administrator to crash the
hypervisor or, potentially, escalate their privileges, allowing them
to execute arbitrary code at the hypervisor level. (CVE-2012-5513,
Important)

* A flaw in the Reliable Datagram Sockets (RDS) protocol
implementation could allow a local, unprivileged user to cause a
denial of service. (CVE-2012-2372, Moderate)

* A race condition in the way access to inet->opt ip_options was
synchronized in the Linux kernel's TCP/IP protocol suite
implementation. Depending on the network facing applications running
on the system, a remote attacker could possibly trigger this flaw to
cause a denial of service. A local, unprivileged user could use this
flaw to cause a denial of service regardless of the applications the
system runs. (CVE-2012-3552, Moderate)

* The Xen hypervisor implementation did not properly restrict the
period values used to initialize per VCPU periodic timers. A
privileged guest user could cause an infinite loop on the physical
CPU. If the watchdog were enabled, it would detect said loop and panic
the host system. (CVE-2012-4535, Moderate)

* A flaw in the way the Xen hypervisor implementation handled
set_p2m_entry() error conditions could allow a privileged,
fully-virtualized guest user to crash the hypervisor. (CVE-2012-4537,
Moderate)

Red Hat would like to thank Theodore Ts'o for reporting CVE-2012-4508;
the Xen project for reporting CVE-2012-5513, CVE-2012-4535, and
CVE-2012-4537; and Hafid Lin for reporting CVE-2012-3552. Upstream
acknowledges Dmitry Monakhov as the original reporter of
CVE-2012-4508. CVE-2012-2372 was discovered by Li Honggang of Red Hat.

Bug fixes :

* Previously, the interrupt handlers of the qla2xxx driver could clear
pending interrupts right after the IRQ lines were attached during
system start-up. Consequently, the kernel could miss the interrupt
that reported completion of the link initialization, and the qla2xxx
driver then failed to detect all attached LUNs. With this update, the
qla2xxx driver has been modified to no longer clear interrupt bits
after attaching the IRQ lines. The driver now correctly detects all
attached LUNs as expected. (BZ#870118)

* The Ethernet channel bonding driver reported the MII (Media
Independent Interface) status of the bond interface in 802.3ad mode as
being up even though the MII status of all of the slave devices was
down. This could pose a problem if the MII status of the bond
interface was used to determine if failover should occur. With this
update, the agg_device_up() function has been added to the bonding
driver, which allows the driver to report the link status of the bond
interface correctly, that is, down when all of its slaves are down, in
the 802.3ad mode. (BZ#877943)

Enhancements :

* This update backports several changes from the latest upstream
version of the bnx2x driver. The most important change, the
remote-fault link detection feature, allows the driver to periodically
scan the physical link layer for remote faults. If the physical link
appears to be up and a fault is detected, the driver indicates that
the link is down. When the fault is cleared, the driver indicates that
the link is up again. (BZ#870120)

* The INET socket interface has been modified to send a warning
message when the ip_options structure is allocated directly by a
third-party module using the kmalloc() function. (BZ#874973)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues and add these enhancements.
The system must be rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-December/019024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20a5141f"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5513");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/07");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-308.24.1.el5")) flag++;


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
