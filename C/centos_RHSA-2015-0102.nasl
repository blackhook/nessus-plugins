#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0102 and 
# CentOS Errata and Security Advisory 2015:0102 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81089);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-4171", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-7145", "CVE-2014-7822", "CVE-2014-7841");
  script_bugtraq_id(68157, 69396, 69428, 69867, 71081, 72347);
  script_xref(name:"RHSA", value:"2015:0102");

  script_name(english:"CentOS 7 : kernel (CESA-2015:0102)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the Linux kernel's SCTP implementation
validated INIT chunks when performing Address Configuration Change
(ASCONF). A remote attacker could use this flaw to crash the system by
sending a specially crafted SCTP packet to trigger a NULL pointer
dereference on the system. (CVE-2014-7841, Important)

* A race condition flaw was found in the way the Linux kernel's
mmap(2), madvise(2), and fallocate(2) system calls interacted with
each other while operating on virtual memory file system files. A
local user could use this flaw to cause a denial of service.
(CVE-2014-4171, Moderate)

* A NULL pointer dereference flaw was found in the way the Linux
kernel's Common Internet File System (CIFS) implementation handled
mounting of file system shares. A remote attacker could use this flaw
to crash a client system that would mount a file system share from a
malicious server. (CVE-2014-7145, Moderate)

* A flaw was found in the way the Linux kernel's splice() system call
validated its parameters. On certain file systems, a local,
unprivileged user could use this flaw to write past the maximum file
size, and thus crash the system. (CVE-2014-7822, Moderate)

* It was found that the parse_rock_ridge_inode_internal() function of
the Linux kernel's ISOFS implementation did not correctly check
relocated directories when processing Rock Ridge child link (CL) tags.
An attacker with physical access to the system could use a specially
crafted ISO image to crash the system or, potentially, escalate their
privileges on the system. (CVE-2014-5471, CVE-2014-5472, Low)

Red Hat would like to thank Akira Fujita of NEC for reporting the
CVE-2014-7822 issue. The CVE-2014-7841 issue was discovered by Liu Wei
of Red Hat.

This update also fixes the following bugs :

* Previously, a kernel panic could occur if a process reading from a
locked NFS file was killed and the lock was not released properly
before the read operations finished. Consequently, the system crashed.
The code handling file locks has been fixed, and instead of halting,
the system now emits a warning about the unreleased lock. (BZ#1172266)

* A race condition in the command abort handling logic of the ipr
device driver could cause the kernel to panic when the driver received
a response to an abort command prior to receiving other responses to
the aborted command due to the support for multiple interrupts. With
this update, the abort handler waits for the aborted command's
responses first before completing an abort operation. (BZ#1162734)

* Previously, a race condition could occur when changing a Page Table
Entry (PTE) or a Page Middle Directory (PMD) to 'pte_numa' or
'pmd_numa', respectively, causing the kernel to crash. This update
removes the BUG_ON() macro from the __handle_mm_fault() function,
preventing the kernel panic in the aforementioned scenario.
(BZ#1170662)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-January/020915.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f18158f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-January/020916.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32bef1c9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7145");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-123.20.1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / kernel-debug-devel / etc");
}
