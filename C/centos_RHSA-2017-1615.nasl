#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1615 and 
# CentOS Errata and Security Advisory 2017:1615 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101120);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-2583", "CVE-2017-6214", "CVE-2017-7477", "CVE-2017-7645", "CVE-2017-7895");
  script_xref(name:"RHSA", value:"2017:1615");

  script_name(english:"CentOS 7 : kernel (CESA-2017:1615)");
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

* A flaw was found in the way Linux kernel allocates heap memory to
build the scattergather list from a fragment
list(skb_shinfo(skb)->frag_list) in the socket buffer(skb_buff). The
heap overflow occurred if 'MAX_SKB_FRAGS + 1' parameter and
'NETIF_F_FRAGLIST' feature were used together. A remote user or
process could use this flaw to potentially escalate their privilege on
a system. (CVE-2017-7477, Important)

* The NFS2/3 RPC client could send long arguments to the NFS server.
These encoded arguments are stored in an array of memory pages, and
accessed using pointer variables. Arbitrarily long arguments could
make these pointers point outside the array and cause an out-of-bounds
memory access. A remote user or program could use this flaw to crash
the kernel (denial of service). (CVE-2017-7645, Important)

* The NFSv2 and NFSv3 server implementations in the Linux kernel
through 4.10.13 lacked certain checks for the end of a buffer. A
remote attacker could trigger a pointer-arithmetic error or possibly
cause other unspecified impacts using crafted requests related to
fs/nfsd/nfs3xdr.c and fs/nfsd/nfsxdr.c. (CVE-2017-7895, Important)

* The Linux kernel built with the Kernel-based Virtual Machine
(CONFIG_KVM) support was vulnerable to an incorrect segment
selector(SS) value error. The error could occur while loading values
into the SS register in long mode. A user or process inside a guest
could use this flaw to crash the guest, resulting in DoS or
potentially escalate their privileges inside the guest.
(CVE-2017-2583, Moderate)

* A flaw was found in the Linux kernel's handling of packets with the
URG flag. Applications using the splice() and tcp_splice_read()
functionality could allow a remote attacker to force the kernel to
enter a condition in which it could loop indefinitely. (CVE-2017-6214,
Moderate)

Red Hat would like to thank Ari Kauppi for reporting CVE-2017-7895 and
Xiaohan Zhang (Huawei Inc.) for reporting CVE-2017-2583.

Bug Fix(es) :

* Previously, the reserved-pages counter (HugePages_Rsvd) was bigger
than the total-pages counter (HugePages_Total) in the /proc/meminfo
file, and HugePages_Rsvd underflowed. With this update, the HugeTLB
feature of the Linux kernel has been fixed, and HugePages_Rsvd
underflow no longer occurs. (BZ#1445184)

* If a directory on a NFS client was modified while being listed, the
NFS client could restart the directory listing multiple times.
Consequently, the performance of listing the directory was
sub-optimal. With this update, the restarting of the directory listing
happens less frequently. As a result, the performance of listing the
directory while it is being modified has improved. (BZ#1450851)

* The Fibre Channel over Ethernet (FCoE) adapter in some cases failed
to reboot. This update fixes the qla2xxx driver, and FCoE adapter now
reboots as expected. (BZ#1446246)

* When a VM with Virtual Function I/O (VFIO) device was rebooted, the
QEMU process occasionally terminated unexpectedly due to a failed VFIO
Direct Memory Access (DMA) map request. This update fixes the vfio
driver and QEMU no longer crashes in the described situation.
(BZ#1450855)

* When the operating system was booted with the in-box lpfc driver, a
kernel panic occurred on the little-endian variant of IBM Power
Systems. This update fixes lpfc, and the kernel no longer panics in
the described situation. (BZ#1452044)

* When creating or destroying a VM with Virtual Function I/O (VFIO)
devices with 'Hugepages' feature enabled, errors in Direct Memory
Access (DMA) page table entry (PTE) mappings occurred, and QEMU memory
usage behaved unpredictably. This update fixes range computation when
making room for large pages in Input/Output Memory Management Unit
(IOMMU). As a result, errors in DMA PTE mappings no longer occur, and
QEMU has a predictable memory usage in the described situation.
(BZ#1450856)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-June/022489.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?327ae90b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7895");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-514.26.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-514.26.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-514.26.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-514.26.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-514.26.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-514.26.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-514.26.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-514.26.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-514.26.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-514.26.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-514.26.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-514.26.1.el7")) flag++;


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
