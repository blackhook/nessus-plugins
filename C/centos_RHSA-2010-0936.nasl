#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0936 and 
# CentOS Errata and Security Advisory 2010:0936 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51775);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-3432", "CVE-2010-3442");
  script_bugtraq_id(43480, 43787);
  script_xref(name:"RHSA", value:"2010:0936");

  script_name(english:"CentOS 4 : kernel (CESA-2010:0936)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and multiple bugs
are now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

[Update 6 December 2010] The package list in this erratum has been
updated to include the kernel-doc packages for the IA32 architecture.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* A flaw in sctp_packet_config() in the Linux kernel's Stream Control
Transmission Protocol (SCTP) implementation could allow a remote
attacker to cause a denial of service. (CVE-2010-3432, Important)

* A missing integer overflow check in snd_ctl_new() in the Linux
kernel's sound subsystem could allow a local, unprivileged user on a
32-bit system to cause a denial of service or escalate their
privileges. (CVE-2010-3442, Important)

Red Hat would like to thank Dan Rosenberg for reporting CVE-2010-3442.

Bug fixes :

* Forward time drift was observed on virtual machines using PM
timer-based kernel tick accounting and running on KVM or the Microsoft
Hyper-V Server hypervisor. Virtual machines that were booted with the
divider=x kernel parameter set to a value greater than 1 and that
showed the following in the kernel boot messages were subject to this
issue :

time.c: Using PM based timekeeping

Fine grained accounting for the PM timer is introduced which
eliminates this issue. However, this fix uncovered a bug in the Xen
hypervisor, possibly causing backward time drift. If this erratum is
installed in Xen HVM guests that meet the aforementioned conditions,
it is recommended that the host use kernel-xen-2.6.18-194.26.1.el5 or
newer, which includes a fix (BZ#641915) for the backward time drift.
(BZ#629237)

* With multipath enabled, systems would occasionally halt when the
do_cciss_request function was used. This was caused by
wrongly-generated requests. Additional checks have been added to avoid
the aforementioned issue. (BZ#640193)

* A Sun X4200 system equipped with a QLogic HBA spontaneously rebooted
and logged a Hyper-Transport Sync Flood Error to the system event log.
A Maximum Memory Read Byte Count restriction was added to fix this
bug. (BZ#640919)

* For an active/backup bonding network interface with VLANs on top of
it, when a link failed over, it took a minute for the multicast domain
to be rejoined. This was caused by the driver not sending any IGMP
join packets. The driver now sends IGMP join packets and the multicast
domain is rejoined immediately. (BZ#641002)

* Replacing a disk and trying to rebuild it afterwards caused the
system to panic. When a domain validation request for a hot plugged
drive was sent, the mptscsi driver did not validate its existence.
This could result in the driver accessing random memory and causing
the crash. A check has been added that describes the newly-added
device and reloads the iocPg3 data from the firmware if needed.
(BZ#641137)

* An attempt to create a VLAN interface on a bond of two bnx2 adapters
in two switch configurations resulted in a soft lockup after a few
seconds. This was caused by an incorrect use of a bonding pointer.
With this update, soft lockups no longer occur and creating a VLAN
interface works as expected. (BZ#641254)

* Erroneous pointer checks could have caused a kernel panic. This was
due to a critical value not being copied when a network buffer was
duplicated and consumed by multiple portions of the kernel's network
stack. Fixing the copy operation resolved this bug. (BZ#642746)

* A typo in a variable name caused it to be dereferenced in either
mkdir() or create() which could cause a kernel panic. (BZ#643342)

* SCSI high level drivers can submit SCSI commands which would never
be completed when the device was offline. This was caused by a missing
callback for the request to complete the given command. SCSI requests
are now terminated by calling their callback when a device is offline.
(BZ#644816)

* A kernel panic could have occurred on systems due to a recursive
lock in the 3c59x driver. Recursion is now avoided and this kernel
panic no longer occurs. (BZ#648407)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-January/017223.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1da3ccdb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-January/017224.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13f97a97"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/28");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-devel-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-devel-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-89.33.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-89.33.1.EL")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-doc / kernel-hugemem / etc");
}
