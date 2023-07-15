#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-1308-1.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100506);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-10208", "CVE-2016-7910", "CVE-2016-8646", "CVE-2017-5986", "CVE-2017-6353", "CVE-2017-7308");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2017-1308-1)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

- [3.10.0-514.21.1.0.1.el7.OL7]
- [ipc] ipc/sem.c: bugfix for semctl(,,GETZCNT) (Manfred Spraul) [orabug 
22552377]
- Oracle Linux certificates (Alexey Petrenko)
- Oracle Linux RHCK Module Signing Key was compiled into kernel 
(olkmod_signing_key.x509)(<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>alexey.petrenko at oracle.com</A>)
- Update x509.genkey [bug 24817676]

[3.10.0-514.21.1.el7]
- [kernel] sched/core: Fix an SMP ordering race in try_to_wake_up() vs. 
schedule() (Gustavo Duarte) [1441547 1423400]
- [drivers] Set dev->device_rh to NULL after free (Prarit Bhargava) 
[1441544 1414064]
- [security] keys: request_key() should reget expired keys rather than 
give EKEYEXPIRED (David Howells) [1441287 1408330]
- [security] keys: Simplify KEYRING_SEARCH_{NO, DO}_STATE_CHECK flags 
(David Howells) [1441287 1408330]
- [net] packet: fix overflow in check for tp_reserve (Hangbin Liu) 
[1441171 1441172] {CVE-2017-7308}
- [net] packet: fix overflow in check for tp_frame_nr (Hangbin Liu) 
[1441171 1441172] {CVE-2017-7308}
- [net] packet: fix overflow in check for priv area size (Hangbin Liu) 
[1441171 1441172] {CVE-2017-7308}
- [powerpc] pseries: Use H_CLEAR_HPT to clear MMU hash table during 
kexec (Steve Best) [1439812 1423396]
- [netdrv] fjes: Fix wrong netdevice feature flags (Yasuaki Ishimatsu) 
[1439802 1435603]
- [kernel] mlx5e: Implement Fragmented Work Queue (WQ) (Don Dutile) 
[1439164 1368400]
- [netdrv] mlx5e: Copy all L2 headers into inline segment (Don Dutile) 
[1439161 1383013]
- [nvdimm] fix PHYS_PFN/PFN_PHYS mixup (Jeff Moyer) [1439160 1428115]
- [s390] scsi: zfcp: fix rport unblock race with LUN recovery (Hendrik 
Brueckner) [1433413 1421750]
- [fs] gfs2: Avoid alignment hole in struct lm_lockname (Robert S 
Peterson) [1432554 1425450]
- [fs] gfs2: Add missing rcu locking for glock lookup (Robert S 
Peterson) [1432554 1425450]
- [fs] ext4: fix fencepost in s_first_meta_bg validation (Lukas Czerner) 
[1430969 1332503] {CVE-2016-10208}
- [fs] ext4: sanity check the block and cluster size at mount time 
(Lukas Czerner) [1430969 1332503] {CVE-2016-10208}
- [fs] ext4: validate s_first_meta_bg at mount time (Lukas Czerner) 
[1430969 1332503] {CVE-2016-10208}
- [net] sctp: deny peeloff operation on asocs with threads sleeping on 
it (Hangbin Liu) [1429496 1429497] {CVE-2017-5986 CVE-2017-6353}
- [net] sctp: avoid BUG_ON on sctp_wait_for_sndbuf (Hangbin Liu) 
[1429496 1429497] {CVE-2017-5986 CVE-2017-6353}
- [x86] perf/x86/intel/rapl: Make package handling more robust (Jiri 
Olsa) [1443902 1418688]
- [x86] perf/x86/intel/rapl: Convert to hotplug state machine (Jiri 
Olsa) [1443902 1418688]
- [x86] perf/x86: Set pmu->module in Intel PMU modules (Jiri Olsa) 
[1443902 1418688]
- [kernel] sched/core, x86/topology: Fix NUMA in package topology bug 
(Jiri Olsa) [1441645 1369832]
- [kernel] sched: Allow hotplug notifiers to be setup early (Jiri Olsa) 
[1441645 1369832]
- [x86] x86/smpboot: Make logical package management more robust (Prarit 
Bhargava) [1441643 1414054]
- [x86] x86/cpu: Deal with broken firmware (VMWare/XEN) (Prarit 
Bhargava) [1441643 1414054]
- [x86] perf/x86/intel/uncore: Fix hardcoded socket 0 assumption in the 
Haswell init code (Prarit Bhargava) [1426633 1373738]
- [x86] revert 'perf/uncore: Disable uncore on kdump kernel' (Prarit 
Bhargava) [1426633 1373738]
- [x86] smpboot: Init apic mapping before usage (Prarit Bhargava) 
[1426633 1373738]
- [x86] smp: Don't try to poke disabled/non-existent APIC (Prarit 
Bhargava) [1426633 1373738]
- [x86] Handle non enumerated CPU after physical hotplug (Prarit 
Bhargava) [1426633 1373738]
- [block] fix use-after-free in seq file (Denys Vlasenko) [1418550 
1418551] {CVE-2016-7910}
- [crypto] algif_hash - Only export and import on sockets with data 
(Herbert Xu) [1394101 1387632] {CVE-2016-8646}
- [char] hwrng: core - sleep interruptible in read (Amit Shah) [1443503 
1376397]
- [char] hwrng: core - correct error check of kthread_run call (Amit 
Shah) [1443503 1376397]
- [char] hwrng: core - Move hwrng_init call into set_current_rng (Amit 
Shah) [1443503 1376397]
- [char] hwrng: core - Drop current rng in set_current_rng (Amit Shah) 
[1443503 1376397]
- [char] hwrng: core - Do not register device opportunistically (Amit 
Shah) [1443503 1376397]
- [char] hwrng: core - Fix current_rng init/cleanup race yet again (Amit 
Shah) [1443503 1376397]
- [char] hwrng: core - Use struct completion for cleanup_done (Amit 
Shah) [1443503 1376397]
- [char] hwrng: don't init list element we're about to add to list (Amit 
Shah) [1443503 1376397]
- [char] hwrng: don't double-check old_rng (Amit Shah) [1443503 1376397]
- [char] hwrng: fix unregister race (Amit Shah) [1443503 1376397]
- [char] hwrng: use reference counts on each struct hwrng (Amit Shah) 
[1443503 1376397]
- [char] hwrng: move some code out mutex_lock for avoiding underlying 
deadlock (Amit Shah) [1443503 1376397]
- [char] hwrng: place mutex around read functions and buffers (Amit 
Shah) [1443503 1376397]
- [char] virtio-rng: skip reading when we start to remove the device 
(Amit Shah) [1443503 1376397]
- [char] virtio-rng: fix stuck of hot-unplugging busy device (Amit Shah) 
[1443503 1376397]
- [infiniband] ib/mlx5: Resolve soft lock on massive reg MRs (Don 
Dutile) [1444347 1417285]

[3.10.0-514.20.1.el7]
- [powerpc] fadump: Fix the race in crash_fadump() (Steve Best) [1439810 
1420077]
- [kernel] locking/mutex: Explicitly mark task as running after wakeup 
(Gustavo Duarte) [1439803 1423397]
- [netdrv] ixgbe: Force VLNCTRL.VFE to be set in all VMDq paths (Ken 
Cox) [1438421 1383524]
- [fs] nfsv4.0: always send mode in SETATTR after EXCLUSIVE4 (Benjamin 
Coddington) [1437967 1415780]
- [net] fix creation adjacent device symlinks (Adrian Reber) [1436646 
1412898]
- [net] prevent of emerging cross-namespace symlinks (Adrian Reber) 
[1436646 1412898]
- [netdrv] macvlan: unregister net device when netdev_upper_dev_link() 
fails (Adrian Reber) [1436646 1412898]
- [scsi] vmw_pvscsi: return SUCCESS for successful command aborts (Ewan 
Milne) [1435764 1394172]
- [infiniband] ib/uverbs: Fix race between uverbs_close and remove_one 
(Don Dutile) [1435187 1417284]
- [fs] gfs2: Prevent BUG from occurring when normal Withdraws occur 
(Robert S Peterson) [1433882 1404005]
- [fs] jbd2: fix incorrect unlock on j_list_lock (Lukas Czerner) 
[1433881 1403346]
- [fs] xfs: don't wrap ID in xfs_dq_get_next_id (Eric Sandeen) [1433415 
1418182]
- [net] tcp/dccp: avoid starving bh on connect (Paolo Abeni) [1433320 
1401419]
- [fs] xfs: fix up xfs_swap_extent_forks inline extent handling (Eric 
Sandeen) [1432154 1412945]
- [x86] kvm: vmx: handle PML full VMEXIT that occurs during event 
delivery (Radim Krcmar) [1431666 1421296]
- [virt] kvm: vmx: ensure VMCS is current while enabling PML (Radim 
Krcmar) [1431666 1421296]
- [net] ip_tunnel: Create percpu gro_cell (Jiri Benc) [1431197 1424076]
- [x86] kvm: x86: do not save guest-unsupported XSAVE state (Radim 
Krcmar) [1431150 1401767]
- [scsi] mpt3sas: Force request partial completion alignment (Tomas 
Henzl) [1430809 1418286]

[3.10.0-514.19.1.el7]
- [fs] gfs2: Wake up io waiters whenever a flush is done (Robert S 
Peterson) [1437126 1404301]
- [fs] gfs2: Made logd daemon take into account log demand (Robert S 
Peterson) [1437126 1404301]
- [fs] gfs2: Limit number of transaction blocks requested for truncates 
(Robert S Peterson) [1437126 1404301]
- [net] ipv6: addrconf: fix dev refcont leak when DAD failed (Hangbin 
Liu) [1436588 1416105]

[3.10.0-514.18.1.el7]
- [net] ipv6: don't increase size when refragmenting forwarded ipv6 skbs 
(Florian Westphal) [1434589 1430571]
- [net] bridge: drop netfilter fake rtable unconditionally (Florian 
Westphal) [1434589 1430571]
- [net] ipv6: avoid write to a possibly cloned skb (Florian Westphal) 
[1434589 1430571]
- [net] netfilter: bridge: honor frag_max_size when refragmenting 
(Florian Westphal) [1434589 1430571]
- [net] bridge: Add br_netif_receive_skb remove netif_receive_skb_sk 
(Ivan Vecera) [1434589 1352289]

[3.10.0-514.17.1.el7]
- [netdrv] i40e: Be much more verbose about what we can and cannot 
offload (Stefan Assmann) [1433273 1383521]
- [kernel] watchdog: prevent false hardlockup on overloaded system (Don 
Zickus) [1433267 1399881]
- [net] dccp/tcp: fix routing redirect race (Eric Garver) [1433265 1387485]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-May/006956.html"
  );
  script_set_attribute(attribute:"solution", value:"
Update the affected kernel packages. Note that the updated packages
may not be immediately available from the package repository and its
mirrors.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET packet_set_ring Privilege Escalation');
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (rpm_exists(release:"EL7", rpm:"kernel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-3.10.0-514.21.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-abi-whitelists-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-514.21.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-debug-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-514.21.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-debug-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-514.21.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-514.21.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-doc-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-doc-3.10.0-514.21.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-headers-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-514.21.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-514.21.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-libs-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-514.21.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-libs-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-514.21.1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"perf-3.10.0-514.21.1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-perf-3.10.0-514.21.1.0.1.el7")) flag++;


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
