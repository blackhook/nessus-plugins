#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0972 and 
# CentOS Errata and Security Advisory 2008:0972 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37341);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-5093", "CVE-2007-6716", "CVE-2008-1514", "CVE-2008-3272", "CVE-2008-3528", "CVE-2008-4210");
  script_bugtraq_id(30559, 31177, 31368, 31515);
  script_xref(name:"RHSA", value:"2008:0972");

  script_name(english:"CentOS 4 : kernel (CESA-2008:0972)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that resolve several security issues and fix
various bugs are now available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* a flaw was found in the Linux kernel's Direct-IO implementation.
This could have allowed a local unprivileged user to cause a denial of
service. (CVE-2007-6716, Important)

* when running ptrace in 31-bit mode on an IBM S/390 or IBM System z
kernel, a local unprivileged user could cause a denial of service by
reading from or writing into a padding area in the user_regs_struct32
structure. (CVE-2008-1514, Important)

* the do_truncate() and generic_file_splice_write() functions did not
clear the setuid and setgid bits. This could have allowed a local
unprivileged user to obtain access to privileged information.
(CVE-2008-4210, Important)

* Tobias Klein reported a missing check in the Linux kernel's Open
Sound System (OSS) implementation. This deficiency could have led to
an information leak. (CVE-2008-3272, Moderate)

* a potential denial of service attack was discovered in the Linux
kernel's PWC USB video driver. A local unprivileged user could have
used this flaw to bring the kernel USB subsystem into the busy-waiting
state. (CVE-2007-5093, Low)

* the ext2 and ext3 file systems code failed to properly handle
corrupted data structures, leading to a possible local denial of
service issue when read or write operations were performed.
(CVE-2008-3528, Low)

In addition, these updated packages fix the following bugs :

* when using the CIFS 'forcedirectio' option, appending to an open
file on a CIFS share resulted in that file being overwritten with the
data to be appended.

* a kernel panic occurred when a device with PCI ID 8086:10c8 was
present on a system with a loaded ixgbe driver.

* due to an aacraid driver regression, the kernel failed to boot when
trying to load the aacraid driver and printed the following error
message: 'aac_srb: aac_fib_send failed with status: 8195'.

* due to an mpt driver regression, when RAID 1 was configured on
Primergy systems with an LSI SCSI IME 53C1020/1030 controller, the
kernel panicked during boot.

* the mpt driver produced a large number of extraneous debugging
messages when performing a 'Host reset' operation.

* due to a regression in the sym driver, the kernel panicked when a
SCSI hot swap was performed using MCP18 hardware.

* all cores on a multi-core system now scale their frequencies in
accordance with the policy set by the system's CPU frequency governor.

* the netdump subsystem suffered from several stability issues. These
are addressed in this updated kernel.

* under certain conditions, the ext3 file system reported a negative
count of used blocks.

* reading /proc/self/mem incorrectly returned 'Invalid argument'
instead of 'input/output error' due to a regression.

* under certain conditions, the kernel panicked when a USB device was
removed while the system was busy accessing the device.

* a race condition in the kernel could have led to a kernel crash
during the creation of a new process.

All Red Hat Enterprise Linux 4 Users should upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015424.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03430f7b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015425.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b753b77"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015443.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7396bf3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(189, 264, 399);

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"kernel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-devel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-doc-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-78.0.8.EL")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-doc / kernel-hugemem / etc");
}
