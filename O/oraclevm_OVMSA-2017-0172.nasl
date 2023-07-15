#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0172.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105146);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-9191", "CVE-2017-1000405", "CVE-2017-12190", "CVE-2017-12192", "CVE-2017-15649", "CVE-2017-16527", "CVE-2017-16650", "CVE-2017-2618");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2017-0172) (Dirty COW)");
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

  - mm, thp: Do not make page table dirty unconditionally in
    follow_trans_huge_pmd (Kirill A. Shutemov) [Orabug:
    27200879] (CVE-2017-1000405)

  - NFS: Add static NFS I/O tracepoints (Chuck Lever)

  - storvsc: don't assume SG list is contiguous (Aruna
    Ramakrishna) 

  - fix unbalanced page refcounting in bio_map_user_iov
    (Vitaly Mayatskikh) [Orabug: 27069038] (CVE-2017-12190)

  - more bio_map_user_iov leak fixes (Al Viro) [Orabug:
    27069038] (CVE-2017-12190)

  - packet: in packet_do_bind, test fanout with bind_lock
    held (Willem de Bruijn) [Orabug: 27069065]
    (CVE-2017-15649)

  - packet: hold bind lock when rebinding to fanout hook
    (Willem de Bruijn) [Orabug: 27069065] (CVE-2017-15649)

  - net: convert packet_fanout.sk_ref from atomic_t to
    refcount_t (Reshetova, Elena) [Orabug: 27069065]
    (CVE-2017-15649)

  - packet: fix races in fanout_add (Eric Dumazet) [Orabug:
    27069065] (CVE-2017-15649)

  - refcount_t: Introduce a special purpose refcount type
    (Peter Zijlstra) [Orabug: 27069065] (CVE-2017-15649)

  - locking/atomics: Add _[acquire|release|relaxed] variants
    of some atomic operations (Will Deacon) [Orabug:
    27069065] (CVE-2017-15649)

  - net: qmi_wwan: fix divide by 0 on bad descriptors
    (Bj&oslash rn Mork) [Orabug: 27215225] (CVE-2017-16650)

  - ALSA: usb-audio: Kill stray URB at exiting (Takashi
    Iwai) [Orabug: 27148276] (CVE-2017-16527)

  - scsi: Add STARGET_CREATED_REMOVE state to
    scsi_target_state (Ewan D. Milne) [Orabug: 27187217]

  - ocfs2: fix posix_acl_create deadlock (Junxiao Bi)
    [Orabug: 27126129]

  - scsi: Don't abort scsi_scan due to unexpected response
    (John Sobecki) 

  - ocfs2: code clean up for direct io (Ryan Ding)

  - xscore: add dma address check (Zhu Yanjun) [Orabug:
    27076919]

  - KVM: nVMX: Fix loss of L2's NMI blocking state (Wanpeng
    Li) [Orabug: 27062498]

  - KVM: nVMX: track NMI blocking state separately for each
    VMCS (Paolo Bonzini) [Orabug: 27062498]

  - KVM: VMX: require virtual NMI support (Paolo Bonzini)
    [Orabug: 27062498]

  - KVM: nVMX: Fix the NMI IDT-vectoring handling (Wanpeng
    Li) [Orabug: 27062498]

  - uek-rpm: disable CONFIG_NUMA_BALANCING_DEFAULT_ENABLED
    (Fred Herard) 

  - thp: run vma_adjust_trans_huge outside i_mmap_rwsem
    (Kirill A. Shutemov) [Orabug: 27026180]

  - selinux: fix off-by-one in setprocattr (Stephen Smalley)
    [Orabug: 27001717] (CVE-2017-2618) (CVE-2017-2618)
    (CVE-2017-2618)

  - sysctl: Drop reference added by grab_header in
    proc_sys_readdir (Zhou Chengming) [Orabug: 27036903]
    (CVE-2016-9191) (CVE-2016-9191) (CVE-2016-9191)

  - KEYS: prevent KEYCTL_READ on negative key (Eric Biggers)
    [Orabug: 27050248] (CVE-2017-12192)

  - IB/ipoib: For sendonly join free the multicast group on
    leave (Christoph Lameter) [Orabug: 27077718]

  - IB/ipoib: increase the max mcast backlog queue (Doug
    Ledford) 

  - IB/ipoib: Make sendonly multicast joins create the mcast
    group (Doug Ledford) [Orabug: 27077718]

  - IB/ipoib: Expire sendonly multicast joins (Christoph
    Lameter) 

  - IB/ipoib: Suppress warning for send only join failures
    (Jason Gunthorpe) [Orabug: 27077718]

  - IB/ipoib: Clean up send-only multicast joins (Doug
    Ledford) [Orabug: 27077718]

  - netlink: allow to listen 'all' netns (Nicolas Dichtel)
    [Orabug: 27077944]

  - netlink: rename private flags and states (Nicolas
    Dichtel) [Orabug: 27077944]

  - netns: use a spin_lock to protect nsid management
    (Nicolas Dichtel) 

  - netns: notify new nsid outside __peernet2id (Nicolas
    Dichtel) 

  - netns: rename peernet2id to peernet2id_alloc (Nicolas
    Dichtel) 

  - netns: always provide the id to rtnl_net_fill (Nicolas
    Dichtel) 

  - netns: returns always an id in __peernet2id (Nicolas
    Dichtel) 

  - Hang/soft lockup in d_invalidate with simultaneous calls
    (Al Viro) 

  - Revert 'drivers/char/mem.c: deny access in open
    operation when securelevel is set' (Brian Maly) [Orabug:
    27037811]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-December/000803.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9044d20e"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-103.10.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-103.10.1.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
