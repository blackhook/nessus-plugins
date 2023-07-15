#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-1615-1.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101138);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2017-1000364", "CVE-2017-2583", "CVE-2017-6214", "CVE-2017-7477", "CVE-2017-7645", "CVE-2017-7895");
  script_xref(name:"IAVA", value:"2017-A-0288-S");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2017-1615-1) (Stack Clash)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

- [3.10.0-514.26.1.0.1.el7.OL7]
- [ipc] ipc/sem.c: bugfix for semctl(,,GETZCNT) (Manfred Spraul) [orabug 
22552377]
- Oracle Linux certificates (Alexey Petrenko)
- Oracle Linux RHCK Module Signing Key was compiled into kernel 
(olkmod_signing_key.x509)(<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>alexey.petrenko at oracle.com</A>)
- Update x509.genkey [bug 24817676]

[3.10.0-514.26.1.el7]
- [mm] enlarge stack guard gap (Larry Woodman) [1452732 1452733] 
{CVE-2017-1000364}
- Revert: [md] dm mirror: use all available legs on multiple failures 
(Mike Snitzer) [1449176 1383444]

[3.10.0-514.25.1.el7]
- [lib] kobject: grab an extra reference on kobject->sd to allow 
duplicate deletes (Aristeu Rozanski) [1454851 1427252]
- [kernel] module: When modifying a module's text ignore modules which 
are going away too (Aaron Tomlin) [1454684 1386313]
- [kernel] module: Ensure a module's state is set accordingly during 
module coming cleanup code (Aaron Tomlin) [1454684 1386313]
- [net] vxlan: do not output confusing error message (Jiri Benc) 
[1454636 1445054]
- [net] vxlan: correctly handle ipv6.disable module parameter (Jiri 
Benc) [1454636 1445054]
- [iommu] vt-d: fix range computation when making room for large pages 
(Alex Williamson) [1450856 1435612]
- [fs] nfsd: stricter decoding of write-like NFSv2/v3 ops ('J. Bruce 
Fields') [1449282 1443204] {CVE-2017-7895}
- [fs] nfsd4: minor NFSv2/v3 write decoding cleanup ('J. Bruce Fields') 
[1449282 1443204] {CVE-2017-7895}
- [md] dm mirror: use all available legs on multiple failures (Mike 
Snitzer) [1449176 1383444]
- [fs] nfsd: check for oversized NFSv2/v3 arguments ('J. Bruce Fields') 
[1447642 1442407] {CVE-2017-7645}
- [scsi] ses: don't get power status of SES device slot on probe 
(Gustavo Duarte) [1446650 1434768]
- [scsi] ipr: do not set DID_PASSTHROUGH on CHECK CONDITION (Steve Best) 
[1446649 1441747]
- [net] macsec: dynamically allocate space for sglist (Sabrina Dubroca) 
[1445546 1445545] {CVE-2017-7477}
- [net] macsec: avoid heap overflow in skb_to_sgvec (Sabrina Dubroca) 
[1445546 1445545] {CVE-2017-7477}
- [fs] gfs2: Allow glocks to be unlocked after withdraw (Robert S 
Peterson) [1433882 1404005]
- [net] tcp: avoid infinite loop in tcp_splice_read() (Davide Caratti) 
[1430579 1430580] {CVE-2017-6214}
- [mm] vma_merge: correct false positive from 
__vma_unlink->validate_mm_rb (Andrea Arcangeli) [1428840 1374548]
- [mm] vma_merge: fix race vm_page_prot race condition against rmap_walk 
(Andrea Arcangeli) [1428840 1374548]
- [mm] fix use-after-free if memory allocation failed in vma_adjust() 
(Andrea Arcangeli) [1428840 1374548]
- [x86] kvm: x86: fix emulation of 'MOV SS, null selector' (Radim 
Krcmar) [1414742 1414743] {CVE-2017-2583}
- [powerpc] prom: Increase minimum RMA size to 512MB (Gustavo Duarte) 
[1450041 1411321]
- [pci] pciehp: Prioritize data-link event over presence detect (Myron 
Stowe) [1450124 1435818]
- [pci] pciehp: Don't re-read Slot Status when queuing hotplug event 
(Myron Stowe) [1450124 1435818]
- [pci] pciehp: Process all hotplug events before looking for new ones 
(Myron Stowe) [1450124 1435818]
- [pci] pciehp: Rename pcie_isr() locals for clarity (Myron Stowe) 
[1450124 1435818]

[3.10.0-514.24.1.el7]
- [scsi] lpfc: Fix panic on BFS configuration (Maurizio Lombardi) 
[1452044 1443116]
- [vfio] type1: Reduce repetitive calls in vfio_pin_pages_remote() (Alex 
Williamson) [1450855 1438403]
- [vfio] type1: Remove locked page accounting workqueue (Alex 
Williamson) [1450855 1438403]
- [fs] nfs: Allow getattr to also report readdirplus cache hits (Dave 
Wysochanski) [1450851 1442068]
- [fs] nfs: Be more targeted about readdirplus use when doing 
lookup/revalidation (Dave Wysochanski) [1450851 1442068]
- [fs] nfs: Fix a performance regression in readdir (Dave Wysochanski) 
[1450851 1442068]
- [x86] xen: do not re-use pirq number cached in pci device msi msg data 
(Vitaly Kuznetsov) [1450037 1433831]
- [powerpc] mm: Add missing global TLB invalidate if cxl is active 
(Steve Best) [1449178 1440776]
- [powerpc] boot: Fix zImage TOC alignment (Gustavo Duarte) [1444343 
1395838]

[3.10.0-514.23.1.el7]
- [scsi] qla2xxx: Defer marking device lost when receiving an RSCN 
(Himanshu Madhani) [1446246 1436940]
- [scsi] qla2xxx: Fix typo in driver (Himanshu Madhani) [1446246 1436940]
- [scsi] qla2xxx: Fix crash in qla2xxx_eh_abort on bad ptr (Himanshu 
Madhani) [1446246 1436940]
- [scsi] qla2xxx: Avoid that issuing a LIP triggers a kernel crash 
(Himanshu Madhani) [1446246 1436940]
- [scsi] qla2xxx: Add fix to read correct register value for ISP82xx 
(Himanshu Madhani) [1446246 1436940]
- [scsi] qla2xxx: Disable the adapter and skip error recovery in case of 
register disconnect (Himanshu Madhani) [1446246 1436940]

[3.10.0-514.22.1.el7]
- [mm] hugetlb: don't use reserved during VM_SHARED mapping cow (Larry 
Woodman) [1445184 1385473]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-June/007023.html"
  );
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages. Note that the updated package may
not be immediately available from the package repository or its
mirrors."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'rsh_stack_clash_priv_esc.rb');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_exists(release:"EL7", rpm:"kernel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-3.10.0-514.26.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-abi-whitelists-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-514.26.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-debug-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-514.26.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-debug-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-514.26.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-514.26.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-doc-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-doc-3.10.0-514.26.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-headers-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-514.26.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-514.26.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-libs-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-514.26.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-libs-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-514.26.1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"perf-3.10.0-514.26.1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-perf-3.10.0-514.26.1.0.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
