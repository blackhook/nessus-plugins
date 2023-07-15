#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1033 and 
# CentOS Errata and Security Advisory 2016:1033 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91105);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-0758", "CVE-2016-3044");
  script_xref(name:"RHSA", value:"2016:1033");

  script_name(english:"CentOS 7 : kernel (CESA-2016:1033)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* A flaw was found in the way the Linux kernel's ASN.1 DER decoder
processed certain certificate files with tags of indefinite length. A
local, unprivileged user could use a specially crafted X.509
certificate DER file to crash the system or, potentially, escalate
their privileges on the system. (CVE-2016-0758, Important)

Red Hat would like to thank Philip Pettersson of Samsung for reporting
this issue.

Bug Fix(es) :

* Under certain conditions, the migration threads could race with the
CPU hotplug, which could cause a deadlock. A set of patches has been
provided to fix this bug, and the deadlock no longer occurs in the
system. (BZ# 1299338)

* A bug in the code that cleans up revoked delegations could
previously cause a soft lockup in the NFS server. This patch fixes the
underlying source code, so the lockup no longer occurs. (BZ#1311582)

* The second attempt to reload Common Application Programming
Interface (CAPI) devices on the little-endian variant of IBM Power
Systems previously failed. The provided set of patches fixes this bug,
and reloading works as intended. (BZ#1312396)

* Due to inconsistencies in page size of IOMMU, the NVMe device, and
the kernel, the BUG_ON signal previously occurred in the
nvme_setup_prps() function, leading to the system crash while setting
up the DMA transfer. The provided patch sets the default NVMe page
size to 4k, thus preventing the system crash. (BZ#1312399)

* Previously, on a system using the Infiniband mlx5 driver used for
the SRP stack, a hard lockup previously occurred after the kernel
exceeded time with lock held with interrupts blocked. As a
consequence, the system panicked. This update fixes this bug, and the
system no longer panics in this situation. (BZ#1313814)

* On the little-endian variant of IBM Power Systems, the kernel
previously crashed in the bitmap_weight() function while running the
memory affinity script. The provided patch fortifies the topology
setup and prevents sd-> child from being set to NULL when it is
already NULL. As a result, the memory affinity script runs
successfully. (BZ#1316158)

* When a KVM guest wrote random values to the special-purpose
registers (SPR) Instruction Authority Mask Register (IAMR), the guest
and the corresponding QEMU process previously hung. This update adds
the code which sets SPRs to a suitable neutral value on guest exit,
thus fixing this bug. (BZ#1316636)

* Under heavy iSCSI traffic load, the system previously panicked due
to a race in the locking code leading to a list corruption. This
update fixes this bug, and the system no longer panics in this
situation. (BZ#1316812)

* During SCSI exception handling (triggered by some irregularities),
the driver could previously use an already retired SCSI command. As a
consequence, a kernel panic or data corruption occurred. The provided
patches fix this bug, and exception handling now proceeds
successfully. (BZ #1316820)

* When the previously opened /dev/tty, which pointed to a pseudo
terminal (pty) pair, was the last file closed, a kernel crash could
previously occur. The underlying source code has been fixed,
preventing this bug. (BZ# 1320297)

* Previously, when using VPLEX and FCoE via the bnx2fc driver,
different degrees of data corruption occurred. The provided patch
fixes the FCP Response (RSP) residual parsing in bnx2fc, which
prevents the aforementioned corruption. (BZ#1322279)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-May/021878.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7135172c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0758");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-327.18.2.el7")) flag++;


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
