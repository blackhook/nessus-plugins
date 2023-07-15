#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0273.
#

include("compat.inc");

if (description)
{
  script_id(119010);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2017-13168", "CVE-2018-14734", "CVE-2018-15572", "CVE-2018-7757");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0273)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - hugetlbfs: fix kernel BUG at fs/hugetlbfs/inode.c:447!
    (Mike Kravetz) 

  - scsi: libsas: fix memory leak in sas_smp_get_phy_events
    (Jason Yan) [Orabug: 27927687] (CVE-2018-7757)

  - KVM: vmx: shadow more fields that are read/written on
    every vmexits (Paolo Bonzini) [Orabug: 28581045]

  - vhost/scsi: Use common handling code in request queue
    handler (Bijan Mottahedeh) [Orabug: 28775573]

  - vhost/scsi: Extract common handling code from control
    queue handler (Bijan Mottahedeh) [Orabug: 28775573]

  - vhost/scsi: Respond to control queue operations (Bijan
    Mottahedeh) 

  - scsi: lpfc: devloss timeout race condition caused null
    pointer reference (James Smart) [Orabug: 27994179]

  - scsi: qla2xxx: Fix race condition between iocb timeout
    and initialisation (Ben Hutchings) [Orabug: 28013813]

  - i40e: Add programming descriptors to cleaned_count
    (Alexander Duyck) 

  - i40e: Fix memory leak related filter programming status
    (Alexander Duyck) [Orabug: 28228724]

  - xen-swiotlb: use actually allocated size on check
    physical continuous (Joe Jin) [Orabug: 28258102]

  - Revert 'Revert 'xen-swiotlb: fix the check condition for
    xen_swiotlb_free_coherent'' (Dongli Zhang) [Orabug:
    28258102]

  - net/mlx4_en: fix potential use-after-free with
    dma_unmap_page (Sarah Newman) [Orabug: 28376051]

  - ocfs2: fix ocfs2 read block panic (Junxiao Bi) [Orabug:
    28580543]

  - block: fix bdi vs gendisk lifetime mismatch (Dan
    Williams) [Orabug: 28645416]

  - e1000e: Fix link check race condition (Benjamin Poirier)
    [Orabug: 28716958]

  - Revert 'e1000e: Separate signaling for link check/link
    up' (Benjamin Poirier) [Orabug: 28716958]

  - e1000e: Avoid missed interrupts following ICR read
    (Benjamin Poirier) 

  - e1000e: Fix queue interrupt re-raising in Other
    interrupt (Benjamin Poirier) [Orabug: 28716958]

  - Partial revert 'e1000e: Avoid receiver overrun interrupt
    bursts' (Benjamin Poirier) [Orabug: 28716958]

  - e1000e: Remove Other from EIAC (Benjamin Poirier)
    [Orabug: 28716958]

  - Fix error code in nfs_lookup_verify_inode (Lance
    Shelton) [Orabug: 28789030]

  - workqueue: Allow modifying low level unbound workqueue
    cpumask (Lai Jiangshan) [Orabug: 28813166]

  - workqueue: Create low-level unbound workqueues cpumask
    (Frederic Weisbecker) [Orabug: 28813166]

  - scsi: sg: mitigate read/write abuse (Jann Horn) [Orabug:
    28824718] (CVE-2017-13168)

  - Revert 'rds: RDS (tcp) hangs on sendto to unresponding
    address' (Brian Maly) [Orabug: 28837953]

  - x86/speculation: Retpoline should always be available on
    Skylake (Alexandre Chartre) [Orabug: 28801831]

  - x86/speculation: Add sysfs entry to enable/disable
    retpoline (Alexandre Chartre) [Orabug: 28607548]

  - x86/speculation: Switch to IBRS when loading a
    non-retpoline module (Alexandre Chartre) [Orabug:
    28607548]

  - x86/speculation: Remove unnecessary retpoline
    alternatives (Alexandre Chartre) [Orabug: 28607548]

  - x86/speculation: Use static key to enable/disable
    retpoline (Alexandre Chartre) [Orabug: 28607548]

  - locking/static_keys: Provide DECLARE and well as DEFINE
    macros (Tony Luck) [Orabug: 28607548]

  - jump_label: remove bug.h, atomic.h dependencies for
    HAVE_JUMP_LABEL (Jason Baron) [Orabug: 28607548]

  - locking/static_key: Fix concurrent static_key_slow_inc
    (Paolo Bonzini) [Orabug: 28607548]

  - jump_label: make static_key_enabled work on
    static_key_true/false types too (Tejun Heo) [Orabug:
    28607548]

  - locking/static_keys: Fix up the static keys
    documentation (Jonathan Corbet) [Orabug: 28607548]

  - locking/static_keys: Fix a silly typo (Jonathan Corbet)
    [Orabug: 28607548]

  - jump label, locking/static_keys: Update docs (Jason
    Baron) [Orabug: 28607548]

  - x86/asm: Add asm macros for static keys/jump labels
    (Andy Lutomirski) 

  - x86/asm: Error out if asm/jump_label.h is included
    inappropriately (Andy Lutomirski) [Orabug: 28607548]

  - jump_label/x86: Work around asm build bug on
    older/backported GCCs (Peter Zijlstra) [Orabug:
    28607548]

  - locking/static_keys: Add a new static_key interface
    (Peter Zijlstra) 

  - locking/static_keys: Rework update logic (Peter
    Zijlstra) [Orabug: 28607548]

  - jump_label: Add jump_entry_key helper (Peter Zijlstra)
    [Orabug: 28607548]

  - jump_label, locking/static_keys: Rename
    JUMP_LABEL_TYPE_* and related helpers to the static_key*
    pattern (Peter Zijlstra) [Orabug: 28607548]

  - jump_label: Rename JUMP_LABEL_[EN,DIS]ABLE to
    JUMP_LABEL_[JMP,NOP] (Peter Zijlstra) [Orabug: 28607548]

  - module, jump_label: Fix module locking (Peter Zijlstra)
    [Orabug: 28607548]

  - x86/speculation: Protect against userspace-userspace
    spectreRSB (Jiri Kosina) [Orabug: 28631590]
    (CVE-2018-15572)

  - x86/spectre_v2: Remove remaining references to lfence
    mitigation (Alejandro Jimenez) [Orabug: 28631590]
    (CVE-2018-15572)

  - Revert 'md: allow a partially recovered device to be
    hot-added to an array.' (NeilBrown) [Orabug: 28702623]

  - x86/bugs: ssbd_ibrs_selected called prematurely (Daniel
    Jordan) 

  - net/mlx4_core: print firmware version during driver
    loading (Qing Huang) [Orabug: 28809377]

  - mm: numa: Do not trap faults on shared data section
    pages. (Henry Willard) [Orabug: 28814880]

  - hugetlbfs: dirty pages as they are added to pagecache
    (Mike Kravetz) 

  - rds: RDS (tcp) hangs on sendto to unresponding address
    (Ka-Cheong Poon) [Orabug: 28762608]

  - nfs: fix a deadlock in nfs client initialization (Scott
    Mayhew) 

  - infiniband: fix a possible use-after-free bug (Cong
    Wang) [Orabug: 28774517] (CVE-2018-14734)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-November/000907.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b815d8a5"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.21.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.21.1.el6uek")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
