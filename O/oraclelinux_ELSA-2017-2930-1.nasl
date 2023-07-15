#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-2930-1.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104088);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-8399", "CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-1000251", "CVE-2017-11176", "CVE-2017-14106", "CVE-2017-7184", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-7558");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2017-2930-1) (BlueBorne)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

- [3.10.0-693.5.2.0.1.el7.OL7]
- [ipc] ipc/sem.c: bugfix for semctl(,,GETZCNT) (Manfred Spraul) [orabug 
22552377]
- Oracle Linux certificates (Alexey Petrenko)
- Oracle Linux RHCK Module Signing Key was compiled into kernel 
(olkmod_signing_key.x509)(<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>alexey.petrenko at oracle.com</A>)
- Update x509.genkey [bug 24817676]

[3.10.0-693.5.2.el7]
- [mm] page_cgroup: Fix Kernel bug during boot with memory cgroups 
enabled (Larry Woodman) [1491970 1483747]
- Revert: [mm] Fix Kernel bug during boot with memory cgroups enabled 
(Larry Woodman) [1491970 1483747]

[3.10.0-693.5.1.el7]
- [netdrv] i40e: point wb_desc at the nvm_wb_desc during 
i40e_read_nvm_aq (Stefan Assmann) [1491972 1484232]
- [netdrv] i40e: avoid NVM acquire deadlock during NVM update (Stefan 
Assmann) [1491972 1484232]
- [mm] Fix Kernel bug during boot with memory cgroups enabled (Larry 
Woodman) [1491970 1483747]
- [fs] nfsv4: Ensure we don't re-test revoked and freed stateids (Dave 
Wysochanski) [1491969 1459733]
- [netdrv] bonding: commit link status change after propose (Jarod 
Wilson) [1491121 1469790]
- [mm] page_alloc: ratelimit PFNs busy info message (Jonathan Toppins) 
[1491120 1383179]
- [netdrv] cxgb4: avoid crash on PCI error recovery path (Gustavo 
Duarte) [1489872 1456990]
- [scsi] Add STARGET_CREATED_REMOVE state to scsi_target_state (Ewan 
Milne) [1489814 1468727]
- [net] tcp: initialize rcv_mss to TCP_MIN_MSS instead of 0 (Davide 
Caratti) [1488341 1487061] {CVE-2017-14106}
- [net] tcp: fix 0 divide in __tcp_select_window() (Davide Caratti) 
[1488341 1487061] {CVE-2017-14106}
- [net] sctp: Avoid out-of-bounds reads from address storage (Stefano 
Brivio) [1484356 1484355] {CVE-2017-7558}
- [net] udp: consistently apply ufo or fragmentation (Davide Caratti) 
[1481530 1481535] {CVE-2017-1000112}
- [net] udp: account for current skb length when deciding about UFO 
(Davide Caratti) [1481530 1481535] {CVE-2017-1000112}
- [net] ipv4: Should use consistent conditional judgement for ip 
fragment in __ip_append_data and ip_finish_output (Davide Caratti) 
[1481530 1481535] {CVE-2017-1000112}
- [net] udp: avoid ufo handling on IP payload compression packets 
(Stefano Brivio) [1490263 1464161]
- [pci] hv: Use vPCI protocol version 1.2 (Vitaly Kuznetsov) [1478256 
1459202]
- [pci] hv: Add vPCI version protocol negotiation (Vitaly Kuznetsov) 
[1478256 1459202]
- [pci] hv: Use page allocation for hbus structure (Vitaly Kuznetsov) 
[1478256 1459202]
- [pci] hv: Fix comment formatting and use proper integer fields (Vitaly 
Kuznetsov) [1478256 1459202]
- [net] ipv6: accept 64k - 1 packet length in ip6_find_1stfragopt() 
(Stefano Brivio) [1477007 1477010] {CVE-2017-7542}
- [net] ipv6: avoid overflow of offset in ip6_find_1stfragopt (Sabrina 
Dubroca) [1477007 1477010] {CVE-2017-7542}
- [net] xfrm_user: validate XFRM_MSG_NEWAE incoming ESN size harder 
(Hannes Frederic Sowa) [1435672 1435670] {CVE-2017-7184}
- [net] xfrm_user: validate XFRM_MSG_NEWAE XFRMA_REPLAY_ESN_VAL 
replay_window (Hannes Frederic Sowa) [1435672 1435670] {CVE-2017-7184}
- [net] l2cap: prevent stack overflow on incoming bluetooth packet (Neil 
Horman) [1489788 1489789] {CVE-2017-1000251}

[3.10.0-693.4.1.el7]
- [fs] nfsv4: Add missing nfs_put_lock_context() (Benjamin Coddington) 
[1487271 1476826]
- [fs] nfs: discard nfs_lockowner structure (Benjamin Coddington) 
[1487271 1476826]
- [fs] nfsv4: enhance nfs4_copy_lock_stateid to use a flock stateid if 
there is one (Benjamin Coddington) [1487271 1476826]
- [fs] nfsv4: change nfs4_select_rw_stateid to take a lock_context 
inplace of lock_owner (Benjamin Coddington) [1487271 1476826]
- [fs] nfsv4: change nfs4_do_setattr to take an open_context instead of 
a nfs4_state (Benjamin Coddington) [1487271 1476826]
- [fs] nfsv4: add flock_owner to open context (Benjamin Coddington) 
[1487271 1476826]
- [fs] nfs: remove l_pid field from nfs_lockowner (Benjamin Coddington) 
[1487271 1476826]
- [x86] platform/uv/bau: Disable BAU on single hub configurations (Frank 
Ramsay) [1487159 1487160 1472455 1473353]
- [x86] platform/uv/bau: Fix congested_response_us not taking effect 
(Frank Ramsay) [1487159 1472455]
- [fs] cifs: Disable encryption capability for RHEL 7.4 kernel (Sachin 
Prabhu) [1485445 1485445]
- [fs] sunrpc: Handle EADDRNOTAVAIL on connection failures (Dave 
Wysochanski) [1484269 1479043]
- [fs] include/linux/printk.h: include pr_fmt in pr_debug_ratelimited 
(Sachin Prabhu) [1484267 1472823]
- [fs] printk: pr_debug_ratelimited: check state first to reduce 
'callbacks suppressed' messages (Sachin Prabhu) [1484267 1472823]
- [net] packet: fix tp_reserve race in packet_set_ring (Stefano Brivio) 
[1481938 1481940] {CVE-2017-1000111}
- [fs] proc: revert /proc/<pid>/maps [stack:TID] annotation (Waiman 
Long) [1481724 1448534]
- [net] ping: check minimum size on ICMP header length (Matteo Croce) 
[1481578 1481573] {CVE-2016-8399}
- [ipc] mqueue: fix a use-after-free in sys_mq_notify() (Davide Caratti) 
[1476128 1476126] {CVE-2017-11176}
- [netdrv] brcmfmac: fix possible buffer overflow in 
brcmf_cfg80211_mgmt_tx() (Stanislaw Gruszka) [1474778 1474784] 
{CVE-2017-7541}

[3.10.0-693.3.1.el7]
- [block] blk-mq-tag: fix wakeup hang after tag resize (Ming Lei) 
[1487281 1472434]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-October/007297.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}

# Temp disable
exit(1, 'Temporarily disabled.');

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
if (rpm_exists(release:"EL7", rpm:"kernel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-3.10.0-693.5.2.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-abi-whitelists-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-693.5.2.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-debug-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-693.5.2.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-debug-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-693.5.2.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-693.5.2.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-doc-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-doc-3.10.0-693.5.2.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-headers-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-693.5.2.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-693.5.2.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-libs-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-693.5.2.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-libs-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-693.5.2.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"perf-3.10.0-693.5.2.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-perf-3.10.0-693.5.2.0.1.el7")) flag++;


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
