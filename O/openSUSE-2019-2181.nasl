#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2181.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(129345);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/31");

  script_cve_id("CVE-2017-18551", "CVE-2018-20976", "CVE-2018-21008", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14835", "CVE-2019-15030", "CVE-2019-15031", "CVE-2019-15090", "CVE-2019-15098", "CVE-2019-15099", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15214", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15217", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15222", "CVE-2019-15239", "CVE-2019-15290", "CVE-2019-15292", "CVE-2019-15538", "CVE-2019-15666", "CVE-2019-15902", "CVE-2019-15917", "CVE-2019-15919", "CVE-2019-15920", "CVE-2019-15921", "CVE-2019-15924", "CVE-2019-15926", "CVE-2019-15927", "CVE-2019-9456");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-2181)");
  script_summary(english:"Check for the openSUSE-2019-2181 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.1 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2017-18551: There was an out of bounds write in the
    function i2c_smbus_xfer_emulated (bnc#1146163).

  - CVE-2018-20976: A use after free exists, related to
    xfs_fs_fill_super failure (bnc#1146285).

  - CVE-2018-21008: A use-after-free can be caused by the
    function rsi_mac80211_detach in the file
    drivers/net/wireless/rsi/rsi_91x_mac80211.c
    (bnc#1149591).

  - CVE-2019-14814, CVE-2019-14815, CVE-2019-14816: Fix
    three heap-based buffer overflows in marvell wifi chip
    driver kernel, that allowed local users to cause a
    denial of service (system crash) or possibly execute
    arbitrary code. (bnc#1146516 bnc#1146512 bnc#1146514)

  - CVE-2019-14835: A buffer overflow flaw was found in the
    way Linux kernel's vhost functionality that translates
    virtqueue buffers to IOVs, logged the buffer descriptors
    during migration. A privileged guest user able to pass
    descriptors with invalid length to the host when
    migration is underway, could use this flaw to increase
    their privileges on the host (bnc#1150112).

  - CVE-2019-15030: In the Linux kernel on the powerpc
    platform, a local user can read vector registers of
    other users' processes via a Facility Unavailable
    exception. To exploit the venerability, a local user
    starts a transaction (via the hardware transactional
    memory instruction tbegin) and then accesses vector
    registers. At some point, the vector registers will be
    corrupted with the values from a different local Linux
    process because of a missing
    arch/powerpc/kernel/process.c check (bnc#1149713).

  - CVE-2019-15031: In the Linux kernel on the powerpc
    platform, a local user can read vector registers of
    other users' processes via an interrupt. To exploit the
    venerability, a local user starts a transaction (via the
    hardware transactional memory instruction tbegin) and
    then accesses vector registers. At some point, the
    vector registers will be corrupted with the values from
    a different local Linux process, because MSR_TM_ACTIVE
    is misused in arch/powerpc/kernel/process.c
    (bnc#1149713).

  - CVE-2019-15090: In the qedi_dbg_* family of functions,
    there was an out-of-bounds read (bnc#1146399).

  - CVE-2019-15098: drivers/net/wireless/ath/ath6kl/usb.c in
    the Linux kernel had a NULL pointer dereference via an
    incomplete address in an endpoint descriptor
    (bnc#1146378 1146543).

  - CVE-2019-15099: drivers/net/wireless/ath/ath10k/usb.c in
    the Linux kernel had a NULL pointer dereference via an
    incomplete address in an endpoint descriptor
    (bnc#1146368).

  - CVE-2019-15117: parse_audio_mixer_unit in
    sound/usb/mixer.c in the Linux kernel mishandled a short
    descriptor, leading to out-of-bounds memory access
    (bnc#1145920).

  - CVE-2019-15118: check_input_term in sound/usb/mixer.c in
    the Linux kernel mishandled recursion, leading to kernel
    stack exhaustion (bnc#1145922).

  - CVE-2019-15211: There was a use-after-free caused by a
    malicious USB device in the
    drivers/media/v4l2-core/v4l2-dev.c driver because
    drivers/media/radio/radio-raremono.c did not properly
    allocate memory (bnc#1146519).

  - CVE-2019-15212: There was a double-free caused by a
    malicious USB device in the drivers/usb/misc/rio500.c
    driver (bnc#1146391).

  - CVE-2019-15214: There was a use-after-free in the sound
    subsystem because card disconnection causes certain data
    structures to be deleted too early. This is related to
    sound/core/init.c and sound/core/info.c (bnc#1146550).

  - CVE-2019-15215: There was a use-after-free caused by a
    malicious USB device in the
    drivers/media/usb/cpia2/cpia2_usb.c driver
    (bnc#1146425).

  - CVE-2019-15216: There was a NULL pointer dereference
    caused by a malicious USB device in the
    drivers/usb/misc/yurex.c driver (bnc#1146361).

  - CVE-2019-15217: There was a NULL pointer dereference
    caused by a malicious USB device in the
    drivers/media/usb/zr364xx/zr364xx.c driver
    (bnc#1146547).

  - CVE-2019-15218: There was a NULL pointer dereference
    caused by a malicious USB device in the
    drivers/media/usb/siano/smsusb.c driver (bnc#1146413).

  - CVE-2019-15219: There was a NULL pointer dereference
    caused by a malicious USB device in the
    drivers/usb/misc/sisusbvga/sisusb.c driver
    (bnc#1146524).

  - CVE-2019-15220: There was a use-after-free caused by a
    malicious USB device in the
    drivers/net/wireless/intersil/p54/p54usb.c driver
    (bnc#1146526).

  - CVE-2019-15221: There was a NULL pointer dereference
    caused by a malicious USB device in the
    sound/usb/line6/pcm.c driver (bnc#1146529).

  - CVE-2019-15222: There was a NULL pointer dereference
    caused by a malicious USB device in the
    sound/usb/helper.c (motu_microbookii) driver
    (bnc#1146531).

  - CVE-2019-15239: In the Linux kernel, a certain
    net/ipv4/tcp_output.c change, which was properly
    incorporated into 4.16.12, was incorrectly backported to
    the earlier longterm kernels, introducing a new
    vulnerability that was potentially more severe than the
    issue that was intended to be fixed by backporting.
    Specifically, by adding to a write queue between
    disconnection and re-connection, a local attacker can
    trigger multiple use-after-free conditions. This can
    result in a kernel crash, or potentially in privilege
    escalation. (for example) Linux distributions that use
    4.9.x longterm kernels or 4.14.x longterm kernels
    (bnc#1146589)

  - CVE-2019-15290: There was a NULL pointer dereference
    caused by a malicious USB device in the
    ath6kl_usb_alloc_urb_from_pipe function in the
    drivers/net/wireless/ath/ath6kl/usb.c driver
    (bnc#1146378 1146543).

  - CVE-2019-15292: There was a use-after-free in
    atalk_proc_exit, related to net/appletalk/atalk_proc.c,
    net/appletalk/ddp.c, and
    net/appletalk/sysctl_net_atalk.c (bnc#1146678).

  - CVE-2019-15538: XFS partially wedges when a chgrp fails
    on account of being out of disk quota.
    xfs_setattr_nonsize is failing to unlock the ILOCK after
    the xfs_qm_vop_chown_reserve call fails. This is
    primarily a local DoS attack vector, but it might result
    as well in remote DoS if the XFS filesystem is exported
    for instance via NFS (bnc#1148093).

  - CVE-2019-15666: There was an out-of-bounds array access
    in __xfrm_policy_unlink, which will cause denial of
    service, because verify_newpolicy_info in
    net/xfrm/xfrm_user.c mishandled directory validation
    (bnc#1148394).

  - CVE-2019-15902: Misuse of the upstream 'x86/ptrace: Fix
    possible spectre-v1 in ptrace_get_debugreg()' commit
    reintroduced the Spectre vulnerability that it aimed to
    eliminate. This occurred because the backport process
    depends on cherry picking specific commits, and because
    two (correctly ordered) code lines were swapped
    (bnc#1149376).

  - CVE-2019-15917: There was a use-after-free issue when
    hci_uart_register_dev() fails in hci_uart_set_proto() in
    drivers/bluetooth/hci_ldisc.c (bnc#1149539).

  - CVE-2019-15919: SMB2_write in fs/cifs/smb2pdu.c had a
    use-after-free (bnc#1149552).

  - CVE-2019-15920: An issue was discovered in the Linux
    kernel SMB2_read in fs/cifs/smb2pdu.c had a
    use-after-free. NOTE: this was not fixed correctly in
    5.0.10; see the 5.0.11 ChangeLog, which documents a
    memory leak (bnc#1149626).

  - CVE-2019-15921: There was a memory leak issue when
    idr_alloc() fails in genl_register_family() in
    net/netlink/genetlink.c (bnc#1149602).

  - CVE-2019-15924: fm10k_init_module in
    drivers/net/ethernet/intel/fm10k/fm10k_main.c had a NULL
    pointer dereference because there is no -ENOMEM upon an
    alloc_workqueue failure (bnc#1149612).

  - CVE-2019-15926: Out of bounds access exists in the
    functions ath6kl_wmi_pstream_timeout_event_rx and
    ath6kl_wmi_cac_event_rx in the file
    drivers/net/wireless/ath/ath6kl/wmi.c (bnc#1149527).

  - CVE-2019-15927: An out-of-bounds access exists in the
    function build_audio_procunit in the file
    sound/usb/mixer.c (bnc#1149522).

  - CVE-2019-9456: In the USB monitor driver there is a
    possible OOB write due to a missing bounds check. This
    could lead to local escalation of privilege with System
    execution privileges needed. User interaction is not
    needed for exploitation (bnc#1150025).

The following non-security bugs were fixed :

  - ACPICA: Increase total number of possible Owner IDs
    (bsc#1148859).

  - ACPI: fix false-positive -Wuninitialized warning
    (bsc#1051510).

  - Add missing structs and defines from recent SMB3.1.1
    documentation (bsc#1144333).

  - Add new flag on SMB3.1.1 read (bsc#1144333).

  - address lock imbalance warnings in smbdirect.c
    (bsc#1144333).

  - Add some missing debug fields in server and tcon structs
    (bsc#1144333).

  - add some missing definitions (bsc#1144333).

  - Add some qedf commits to blacklist file (bsc#1149976)

  - Add vers=3.0.2 as a valid option for SMBv3.0.2
    (bsc#1144333).

  - ALSA: firewire: fix a memory leak bug (bsc#1051510).

  - ALSA: hda - Add a generic reboot_notify (bsc#1051510).

  - ALSA: hda - Apply workaround for another AMD chip
    1022:1487 (bsc#1051510).

  - ALSA: hda/ca0132 - Add new SBZ quirk (bsc#1051510).

  - ALSA: hda - Do not override global PCM hw info flag
    (bsc#1051510).

  - ALSA: hda - Fix a memory leak bug (bsc#1051510).

  - ALSA: hda - Fixes inverted Conexant GPIO mic mute led
    (bsc#1051510).

  - ALSA: hda - Fix potential endless loop at applying
    quirks (bsc#1051510).

  - ALSA: hda: kabi workaround for generic parser flag
    (bsc#1051510).

  - ALSA: hda - Let all conexant codec enter D3 when
    rebooting (bsc#1051510).

  - ALSA: hda/realtek - Add quirk for HP Envy x360
    (bsc#1051510).

  - ALSA: hda/realtek - Add quirk for HP Pavilion 15
    (bsc#1051510).

  - ALSA: hda/realtek - Enable internal speaker & headset
    mic of ASUS UX431FL (bsc#1051510).

  - ALSA: hda/realtek - Fix overridden device-specific
    initialization (bsc#1051510).

  - ALSA: hda/realtek - Fix the problem of two front mics on
    a ThinkCentre (bsc#1051510).

  - ALSA: hda - Workaround for crackled sound on AMD
    controller (1022:1457) (bsc#1051510).

  - ALSA: hiface: fix multiple memory leak bugs
    (bsc#1051510).

  - ALSA: line6: Fix memory leak at line6_init_pcm() error
    path (bsc#1051510).

  - ALSA: seq: Fix potential concurrent access to the
    deleted pool (bsc#1051510).

  - ALSA: usb-audio: Add implicit fb quirk for Behringer
    UFX1604 (bsc#1051510).

  - ALSA: usb-audio: Check mixer unit bitmap yet more
    strictly (bsc#1051510).

  - ALSA: usb-audio: fix a memory leak bug (bsc#1111666).

  - ALSA: usb-audio: Fix invalid NULL check in
    snd_emuusb_set_samplerate() (bsc#1051510).

  - arm64: fix undefined reference to 'printk'
    (bsc#1148219).

  - arm64/kernel: enable A53 erratum #8434319 handling at
    runtime (bsc#1148219).

  - arm64/kernel: rename
    module_emit_adrp_veneer->module_emit_veneer_for_adrp
    (bsc#1148219).

  - arm64: module: do not BUG when exceeding preallocated
    PLT count (bsc#1148219).

  - arm64: PCI: Preserve firmware configuration when desired
    (SLE-9332).

  - ASoC: dapm: Fix handling of custom_stop_condition on
    DAPM graph walks (bsc#1051510).

  - ASoC: Fail card instantiation if DAI format setup fails
    (bsc#1051510).

  - ata: libahci: do not complain in case of deferred probe
    (bsc#1051510).

  - ath10k: Change the warning message string (bsc#1051510).

  - ath10k: Drop WARN_ON()s that always trigger during
    system resume (bsc#1111666).

  - batman-adv: fix uninit-value in
    batadv_netlink_get_ifindex() (bsc#1051510).

  - batman-adv: Only read OGM2 tvlv_len after buffer len
    check (bsc#1051510).

  - batman-adv: Only read OGM tvlv_len after buffer len
    check (bsc#1051510).

  - bcache: fix possible memory leak in bch_cached_dev_run()
    (git fixes).

  - bcache: Revert 'bcache: use sysfs_match_string() instead
    of __sysfs_match_string()' (git fixes).

  - bio: fix improper use of smp_mb__before_atomic() (git
    fixes).

  - blk-mq: backport fixes for
    blk_mq_complete_e_request_sync() (bsc#1145661).

  - blk-mq: Fix spelling in a source code comment (git
    fixes).

  - blk-mq: introduce blk_mq_complete_request_sync()
    (bsc#1145661).

  - blk-wbt: Avoid lock contention and thundering herd issue
    in wbt_wait (bsc#1141543).

  - block, documentation: Fix wbt_lat_usec documentation
    (git fixes).

  - Bluetooth: btqca: Add a short delay before downloading
    the NVM (bsc#1051510).

  - bnx2x: Disable multi-cos feature (bsc#1136498
    jsc#SLE-4699).

  - bnx2x: Prevent ptp_task to be rescheduled indefinitely
    (networking-stable-19_07_25).

  - bnxt_en: Fix to include flow direction in L2 key
    (bsc#1104745 FATE#325918).

  - bnxt_en: Fix VNIC clearing logic for 57500 chips
    (bsc#1104745 FATE#325918).

  - bnxt_en: Improve RX doorbell sequence (bsc#1104745
    FATE#325918).

  - bnxt_en: Use correct src_fid to determine direction of
    the flow (bsc#1104745 FATE#325918).

  - bonding: validate ip header before check IPPROTO_IGMP
    (networking-stable-19_07_25).

  - bpf: sockmap, only create entry if ulp is not already
    enabled (bsc#1109837).

  - bpf: sockmap, sock_map_delete needs to use xchg
    (bsc#1109837).

  - bpf: sockmap, synchronize_rcu before free'ing map
    (bsc#1109837).

  - btrfs: add a helper to retrive extent inline ref type
    (bsc#1149325).

  - btrfs: add cleanup_ref_head_accounting helper
    (bsc#1050911).

  - btrfs: add missing inode version, ctime and mtime
    updates when punching hole (bsc#1140487).

  - btrfs: add one more sanity check for shared ref type
    (bsc#1149325).

  - btrfs: clean up pending block groups when transaction
    commit aborts (bsc#1050911).

  - btrfs: convert to use btrfs_get_extent_inline_ref_type
    (bsc#1149325).

  - btrfs: do not abort transaction at btrfs_update_root()
    after failure to COW path (bsc#1150933).

  - btrfs: fix assertion failure during fsync and use of
    stale transaction (bsc#1150562).

  - btrfs: fix data loss after inode eviction, renaming it,
    and fsync it (bsc#1145941).

  - btrfs: Fix delalloc inodes invalidation during
    transaction abort (bsc#1050911).

  - btrfs: fix fsync not persisting dentry deletions due to
    inode evictions (bsc#1145942).

  - btrfs: fix incremental send failure after deduplication
    (bsc#1145940).

  - btrfs: fix pinned underflow after transaction aborted
    (bsc#1050911).

  - btrfs: fix race between send and deduplication that lead
    to failures and crashes (bsc#1145059).

  - btrfs: fix race leading to fs corruption after
    transaction abort (bsc#1145937).

  - btrfs: handle delayed ref head accounting cleanup in
    abort (bsc#1050911).

  - btrfs: prevent send failures and crashes due to
    concurrent relocation (bsc#1145059).

  - btrfs: remove BUG() in add_data_reference (bsc#1149325).

  - btrfs: remove BUG() in btrfs_extent_inline_ref_size
    (bsc#1149325).

  - btrfs: remove BUG() in print_extent_item (bsc#1149325).

  - btrfs: remove BUG_ON in __add_tree_block (bsc#1149325).

  - btrfs: Split btrfs_del_delalloc_inode into 2 functions
    (bsc#1050911).

  - btrfs: start readahead also in seed devices
    (bsc#1144886).

  - btrfs: track running balance in a simpler way
    (bsc#1145059).

  - caif-hsi: fix possible deadlock in cfhsi_exit_module()
    (networking-stable-19_07_25).

  - can: m_can: implement errata 'Needless activation of
    MRAF irq' (bsc#1051510).

  - can: mcp251x: add support for mcp25625 (bsc#1051510).

  - can: peak_usb: fix potential double kfree_skb()
    (bsc#1051510).

  - can: peak_usb: force the string buffer NULL-terminated
    (bsc#1051510).

  - can: peak_usb: pcan_usb_fd: Fix info-leaks to USB
    devices (bsc#1051510).

  - can: peak_usb: pcan_usb_pro: Fix info-leaks to USB
    devices (bsc#1051510).

  - can: rcar_canfd: fix possible IRQ storm on high load
    (bsc#1051510).

  - can: sja1000: force the string buffer NULL-terminated
    (bsc#1051510).

  - carl9170: fix misuse of device driver API (bsc#1142635).

  - ceph: add btime field to ceph_inode_info (bsc#1148133
    bsc#1136682).

  - ceph: add ceph.snap.btime vxattr (bsc#1148133
    bsc#1148570).

  - ceph: add change_attr field to ceph_inode_info
    (bsc#1148133 bsc#1136682).

  - ceph: always get rstat from auth mds (bsc#1146346).

  - ceph: carry snapshot creation time with inodes
    (bsc#1148133 bsc#1148570).

  - ceph: clean up ceph.dir.pin vxattr name sizeof()
    (bsc#1146346).

  - ceph: clear page dirty before invalidate page
    (bsc#1148133).

  - ceph: decode feature bits in session message
    (bsc#1146346).

  - ceph: do not blindly unregister session that is in
    opening state (bsc#1148133).

  - ceph: do not try fill file_lock on unsuccessful
    GETFILELOCK reply (bsc#1148133).

  - ceph: fix buffer free while holding i_ceph_lock in
    __ceph_build_xattrs_blob() (bsc#1148133).

  - ceph: fix buffer free while holding i_ceph_lock in
    __ceph_setxattr() (bsc#1148133).

  - ceph: fix buffer free while holding i_ceph_lock in
    fill_inode() (bsc#1148133).

  - ceph: fix 'ceph.dir.rctime' vxattr value (bsc#1148133
    bsc#1135219).

  - ceph: fix decode_locker to use ceph_decode_entity_addr
    (bsc#1148133 bsc#1136682).

  - ceph: fix improper use of smp_mb__before_atomic()
    (bsc#1148133).

  - ceph: fix infinite loop in get_quota_realm()
    (bsc#1148133).

  - ceph: fix listxattr vxattr buffer length calculation
    (bsc#1148133 bsc#1148570).

  - ceph: handle btime in cap messages (bsc#1148133
    bsc#1136682).

  - ceph: handle change_attr in cap messages (bsc#1148133
    bsc#1136682).

  - ceph: have MDS map decoding use entity_addr_t decoder
    (bsc#1148133 bsc#1136682).

  - ceph: hold i_ceph_lock when removing caps for freeing
    inode (bsc#1148133).

  - ceph: increment change_attribute on local changes
    (bsc#1148133 bsc#1136682).

  - ceph: initialize superblock s_time_gran to 1
    (bsc#1148133).

  - ceph: remove request from waiting list before unregister
    (bsc#1148133).

  - ceph: remove unused vxattr length helpers (bsc#1148133
    bsc#1148570).

  - ceph: silence a checker warning in mdsc_show()
    (bsc#1148133).

  - ceph: support cephfs' own feature bits (bsc#1146346).

  - ceph: support getting ceph.dir.pin vxattr (bsc#1146346).

  - ceph: support versioned reply (bsc#1146346).

  - ceph: use bit flags to define vxattr attributes
    (bsc#1146346).

  - cifs: Accept validate negotiate if server return
    NT_STATUS_NOT_SUPPORTED (bsc#1144333).

  - cifs: add a new SMB2_close_flags function (bsc#1144333).

  - cifs: add a smb2_compound_op and change QUERY_INFO to
    use it (bsc#1144333).

  - cifs: add a timeout argument to wait_for_free_credits
    (bsc#1144333).

  - cifs: add a warning if we try to to dequeue a deleted
    mid (bsc#1144333).

  - cifs: add compound_send_recv() (bsc#1144333).

  - cifs: add credits from unmatched responses/messages
    (bsc#1144333).

  - cifs: add debug output to show nocase mount option
    (bsc#1144333).

  - cifs: Add DFS cache routines (bsc#1144333).

  - cifs: Add direct I/O functions to file_operations
    (bsc#1144333).

  - cifs: add fiemap support (bsc#1144333).

  - cifs: add iface info to struct cifs_ses (bsc#1144333).

  - cifs: add IOCTL for QUERY_INFO passthrough to userspace
    (bsc#1144333).

  - cifs: add lease tracking to the cached root fid
    (bsc#1144333).

  - cifs: Add minor debug message during negprot
    (bsc#1144333).

  - cifs: add missing debug entries for kconfig options
    (bsc#1051510, bsc#1144333).

  - cifs: add missing GCM module dependency (bsc#1144333).

  - cifs: add missing support for ACLs in SMB 3.11
    (bsc#1051510, bsc#1144333).

  - cifs: add ONCE flag for cifs_dbg type (bsc#1144333).

  - cifs: add pdu_size to the TCP_Server_Info structure
    (bsc#1144333).

  - cifs: add resp_buf_size to the mid_q_entry structure
    (bsc#1144333).

  - cifs: address trivial coverity warning (bsc#1144333).

  - cifs: add server argument to the dump_detail method
    (bsc#1144333).

  - cifs: add server->vals->header_preamble_size
    (bsc#1144333).

  - cifs: add SFM mapping for 0x01-0x1F (bsc#1144333).

  - cifs: add sha512 secmech (bsc#1051510, bsc#1144333).

  - cifs: Adds information-level logging function
    (bsc#1144333).

  - cifs: add SMB2_close_init()/SMB2_close_free()
    (bsc#1144333).

  - cifs: add SMB2_ioctl_init/free helpers to be used with
    compounding (bsc#1144333).

  - cifs: add SMB2_query_info_[init|free]() (bsc#1144333).

  - cifs: Add smb2_send_recv (bsc#1144333).

  - cifs: add spinlock for the openFileList to cifsInodeInfo
    (bsc#1144333).

  - cifs: add .splice_write (bsc#1144333).

  - cifs: Add support for direct I/O read (bsc#1144333).

  - cifs: Add support for direct I/O write (bsc#1144333).

  - cifs: Add support for direct pages in rdata
    (bsc#1144333).

  - cifs: Add support for direct pages in wdata
    (bsc#1144333).

  - cifs: Add support for failover in cifs_mount()
    (bsc#1144333).

  - cifs: Add support for failover in cifs_reconnect()
    (bsc#1144333).

  - cifs: Add support for failover in cifs_reconnect_tcon()
    (bsc#1144333).

  - cifs: Add support for failover in smb2_reconnect()
    (bsc#1144333).

  - cifs: Add support for FSCTL passthrough that write data
    to the server (bsc#1144333).

  - cifs: add support for ioctl on directories
    (bsc#1144333).

  - cifs: Add support for reading attributes on SMB2+
    (bsc#1051510, bsc#1144333).

  - cifs: add support for SEEK_DATA and SEEK_HOLE
    (bsc#1144333).

  - cifs: Add support for writing attributes on SMB2+
    (bsc#1051510, bsc#1144333).

  - cifs: Adjust MTU credits before reopening a file
    (bsc#1144333).

  - cifs: Allocate memory for all iovs in smb2_ioctl
    (bsc#1144333).

  - cifs: Allocate validate negotiation request through
    kmalloc (bsc#1144333).

  - cifs: allow calling SMB2_xxx_free(NULL) (bsc#1144333).

  - cifs: allow disabling less secure legacy dialects
    (bsc#1144333).

  - cifs: allow guest mounts to work for smb3.11
    (bsc#1051510, bsc#1144333).

  - cifs: always add credits back for unsolicited PDUs
    (bsc#1144333).

  - cifs: Always reset read error to -EIO if no response
    (bsc#1144333).

  - cifs: Always resolve hostname before reconnecting
    (bsc#1051510, bsc#1144333).

  - cifs: a smb2_validate_and_copy_iov failure does not mean
    the handle is invalid (bsc#1144333).

  - cifs: auto disable 'serverino' in dfs mounts
    (bsc#1144333).

  - cifs: avoid a kmalloc in smb2_send_recv/SendReceive2 for
    the common case (bsc#1144333).

  - cifs: Avoid returning EBUSY to upper layer VFS
    (bsc#1144333).

  - cifs: cache FILE_ALL_INFO for the shared root handle
    (bsc#1144333).

  - cifs: Calculate the correct request length based on page
    offset and tail size (bsc#1144333).

  - cifs: Call MID callback before destroying transport
    (bsc#1144333).

  - cifs: change mkdir to use a compound (bsc#1144333).

  - cifs: change smb2_get_data_area_len to take a
    smb2_sync_hdr as argument (bsc#1144333).

  - cifs: Change SMB2_open to return an iov for the error
    parameter (bsc#1144333).

  - cifs: change SMB2_OP_RENAME and SMB2_OP_HARDLINK to use
    compounding (bsc#1144333).

  - cifs: change SMB2_OP_SET_EOF to use compounding
    (bsc#1144333).

  - cifs: change SMB2_OP_SET_INFO to use compounding
    (bsc#1144333).

  - cifs: change smb2_query_eas to use the compound
    query-info helper (bsc#1144333).

  - cifs: change unlink to use a compound (bsc#1144333).

  - cifs: change validate_buf to validate_iov (bsc#1144333).

  - cifs: change wait_for_free_request() to take flags as
    argument (bsc#1144333).

  - cifs: check CIFS_MOUNT_NO_DFS when trying to reuse
    existing sb (bsc#1144333).

  - cifs: Check for reconnects before sending async requests
    (bsc#1144333).

  - cifs: Check for reconnects before sending compound
    requests (bsc#1144333).

  - cifs: check for STATUS_USER_SESSION_DELETED
    (bsc#1112902, bsc#1144333).

  - cifs: Check for timeout on Negotiate stage (bsc#1091171,
    bsc#1144333).

  - cifs: check if SMB2 PDU size has been padded and
    suppress the warning (bsc#1144333).

  - cifs: check kmalloc before use (bsc#1051510,
    bsc#1144333).

  - cifs: check kzalloc return (bsc#1144333).

  - cifs: check MaxPathNameComponentLength != 0 before using
    it (bsc#1085536, bsc#1144333).

  - cifs: check ntwrk_buf_start for NULL before
    dereferencing it (bsc#1144333).

  - cifs: check rsp for NULL before dereferencing in
    SMB2_open (bsc#1085536, bsc#1144333).

  - cifs: cifs_read_allocate_pages: do not iterate through
    whole page array on ENOMEM (bsc#1144333).

  - cifs: clean up indentation, replace spaces with tab
    (bsc#1144333).

  - cifs: cleanup smb2ops.c and normalize strings
    (bsc#1144333).

  - cifs: complete PDU definitions for interface queries
    (bsc#1144333).

  - cifs: connect to servername instead of IP for IPC$ share
    (bsc#1051510, bsc#1144333).

  - cifs: Count SMB3 credits for malformed pending responses
    (bsc#1144333).

  - cifs: create a define for how many iovs we need for an
    SMB2_open() (bsc#1144333).

  - cifs: create a define for the max number of iov we need
    for a SMB2 set_info (bsc#1144333).

  - cifs: create a helper function for compound query_info
    (bsc#1144333).

  - cifs: create helpers for SMB2_set_info_init/free()
    (bsc#1144333).

  - cifs: create SMB2_open_init()/SMB2_open_free() helpers
    (bsc#1144333).

  - cifs: Display SMB2 error codes in the hex format
    (bsc#1144333).

  - cifs: document tcon/ses/server refcount dance
    (bsc#1144333).

  - cifs: do not allow creating sockets except with SMB1
    posix exensions (bsc#1102097, bsc#1144333).

  - cifs: Do not assume one credit for async responses
    (bsc#1144333).

  - cifs: do not attempt cifs operation on smb2+ rename
    error (bsc#1144333).

  - cifs: Do not consider -ENODATA as stat failure for reads
    (bsc#1144333).

  - cifs: Do not count -ENODATA as failure for query
    directory (bsc#1051510, bsc#1144333).

  - cifs: do not dereference smb_file_target before null
    check (bsc#1051510, bsc#1144333).

  - cifs: Do not hide EINTR after sending network packets
    (bsc#1051510, bsc#1144333).

  - cifs: Do not log credits when unmounting a share
    (bsc#1144333).

  - cifs: do not log STATUS_NOT_FOUND errors for DFS
    (bsc#1051510, bsc#1144333).

  - cifs: Do not match port on SMBDirect transport
    (bsc#1144333).

  - cifs: Do not modify mid entry after submitting I/O in
    cifs_call_async (bsc#1051510, bsc#1144333).

  - cifs: Do not reconnect TCP session in add_credits()
    (bsc#1051510, bsc#1144333).

  - cifs: Do not reset lease state to NONE on lease break
    (bsc#1051510, bsc#1144333).

  - cifs: do not return atime less than mtime (bsc#1144333).

  - cifs: do not send invalid input buffer on QUERY_INFO
    requests (bsc#1144333).

  - cifs: Do not set credits to 1 if the server didn't grant
    anything (bsc#1144333).

  - cifs: do not show domain= in mount output when domain is
    empty (bsc#1144333).

  - cifs: Do not skip SMB2 message IDs on send failures
    (bsc#1144333).

  - cifs: do not use __constant_cpu_to_le32() (bsc#1144333).

  - cifs: dump every session iface info (bsc#1144333).

  - cifs: dump IPC tcon in debug proc file (bsc#1071306,
    bsc#1144333).

  - cifs: fallback to older infolevels on findfirst
    queryinfo retry (bsc#1144333).

  - cifs: Find and reopen a file before get MTU credits in
    writepages (bsc#1144333).

  - cifs: fix a buffer leak in smb2_query_symlink
    (bsc#1144333).

  - cifs: fix a credits leak for compund commands
    (bsc#1144333).

  - cifs: Fix a debug message (bsc#1144333).

  - cifs: Fix adjustment of credits for MTU requests
    (bsc#1051510, bsc#1144333).

  - cifs: Fix an issue with re-sending rdata when transport
    returning -EAGAIN (bsc#1144333).

  - cifs: Fix an issue with re-sending wdata when transport
    returning -EAGAIN (bsc#1144333).

  - cifs: Fix a race condition with cifs_echo_request
    (bsc#1144333).

  - cifs: Fix a tiny potential memory leak (bsc#1144333).

  - cifs: Fix autonegotiate security settings mismatch
    (bsc#1087092, bsc#1144333).

  - cifs: fix bi-directional fsctl passthrough calls
    (bsc#1144333).

  - cifs: fix build break when CONFIG_CIFS_DEBUG2 enabled
    (bsc#1144333).

  - cifs: fix build errors for SMB_DIRECT (bsc#1144333).

  - cifs: Fix check for matching with existing mount
    (bsc#1144333).

  - cifs: fix circular locking dependency (bsc#1064701,
    bsc#1144333).

  - cifs: fix computation for MAX_SMB2_HDR_SIZE
    (bsc#1144333).

  - cifs: fix confusing warning message on reconnect
    (bsc#1144333).

  - cifs: fix crash in cifs_dfs_do_automount (bsc#1144333).

  - cifs: fix crash in
    smb2_compound_op()/smb2_set_next_command()
    (bsc#1144333).

  - cifs: fix crash querying symlinks stored as
    reparse-points (bsc#1144333).

  - cifs: Fix credit calculation for encrypted reads with
    errors (bsc#1051510, bsc#1144333).

  - cifs: Fix credit calculations in compound mid callback
    (bsc#1144333).

  - cifs: Fix credit computation for compounded requests
    (bsc#1144333).

  - cifs: Fix credits calculation for cancelled requests
    (bsc#1144333).

  - cifs: Fix credits calculations for reads with errors
    (bsc#1051510, bsc#1144333).

  - cifs: fix credits leak for SMB1 oplock breaks
    (bsc#1144333).

  - cifs: fix deadlock in cached root handling
    (bsc#1144333).

  - cifs: Fix DFS cache refresher for DFS links
    (bsc#1144333).

  - cifs: fix encryption in SMB3.1.1 (bsc#1144333).

  - cifs: Fix encryption/signing (bsc#1144333).

  - cifs: Fix error mapping for SMB2_LOCK command which
    caused OFD lock problem (bsc#1051510, bsc#1144333).

  - cifs: Fix error paths in writeback code (bsc#1144333).

  - cifs: fix GlobalMid_Lock bug in cifs_reconnect
    (bsc#1144333).

  - cifs: fix handle leak in smb2_query_symlink()
    (bsc#1144333).

  - cifs: fix incorrect handling of smb2_set_sparse() return
    in smb3_simple_falloc (bsc#1144333).

  - cifs: Fix infinite loop when using hard mount option
    (bsc#1091171, bsc#1144333).

  - cifs: Fix invalid check in __cifs_calc_signature()
    (bsc#1144333).

  - cifs: Fix kernel oops when traceSMB is enabled
    (bsc#1144333).

  - cifs: fix kref underflow in close_shroot()
    (bsc#1144333).

  - cifs: Fix leaking locked VFS cache pages in writeback
    retry (bsc#1144333).

  - cifs: Fix lease buffer length error (bsc#1144333).

  - cifs: fix memory leak and remove dead code
    (bsc#1144333).

  - cifs: fix memory leak in SMB2_open() (bsc#1112894,
    bsc#1144333).

  - cifs: fix memory leak in SMB2_read (bsc#1144333).

  - cifs: Fix memory leak in smb2_set_ea() (bsc#1051510,
    bsc#1144333).

  - cifs: fix memory leak of an allocated cifs_ntsd
    structure (bsc#1144333).

  - cifs: fix memory leak of pneg_inbuf on -EOPNOTSUPP ioctl
    case (bsc#1144333).

  - cifs: Fix missing put_xid in cifs_file_strict_mmap
    (bsc#1087092, bsc#1144333).

  - cifs: Fix module dependency (bsc#1144333).

  - cifs: Fix mounts if the client is low on credits
    (bsc#1144333).

  - cifs: fix NULL deref in SMB2_read (bsc#1085539,
    bsc#1144333).

  - cifs: Fix NULL pointer dereference of devname
    (bnc#1129519).

  - cifs: Fix NULL pointer deref on SMB2_tcon() failure
    (bsc#1071009, bsc#1144333).

  - cifs: Fix NULL ptr deref (bsc#1144333).

  - cifs: fix page reference leak with readv/writev
    (bsc#1144333).

  - cifs: fix panic in smb2_reconnect (bsc#1144333).

  - cifs: fix parsing of symbolic link error response
    (bsc#1144333).

  - cifs: fix POSIX lock leak and invalid ptr deref
    (bsc#1114542, bsc#1144333).

  - cifs: Fix possible hang during async MTU reads and
    writes (bsc#1051510, bsc#1144333).

  - cifs: Fix possible oops and memory leaks in async IO
    (bsc#1144333).

  - cifs: Fix potential OOB access of lock element array
    (bsc#1051510, bsc#1144333).

  - cifs: Fix read after write for files with read caching
    (bsc#1051510, bsc#1144333).

  - cifs: fix return value for cifs_listxattr (bsc#1051510,
    bsc#1144333).

  - cifs: fix rmmod regression in cifs.ko caused by
    force_sig changes (bsc#1144333).

  - cifs: Fix separator when building path from dentry
    (bsc#1051510, bsc#1144333).

  - cifs: fix sha512 check in cifs_crypto_secmech_release
    (bsc#1051510, bsc#1144333).

  - cifs: fix signed/unsigned mismatch on aio_read patch
    (bsc#1144333).

  - cifs: Fix signing for SMB2/3 (bsc#1144333).

  - cifs: Fix slab-out-of-bounds in send_set_info() on SMB2
    ACE setting (bsc#1144333).

  - cifs: Fix slab-out-of-bounds when tracing SMB tcon
    (bsc#1144333).

  - cifs: fix SMB1 breakage (bsc#1144333).

  - cifs: fix smb3_zero_range for Azure (bsc#1144333).

  - cifs: fix smb3_zero_range so it can expand the file-size
    when required (bsc#1144333).

  - cifs: fix sparse warning on previous patch in a few
    printks (bsc#1144333).

  - cifs: fix spelling mistake, EACCESS -> EACCES
    (bsc#1144333).

  - cifs: Fix stack out-of-bounds in
    smb(2,3)_create_lease_buf() (bsc#1051510, bsc#1144333).

  - cifs: fix strcat buffer overflow and reduce raciness in
    smb21_set_oplock_level() (bsc#1144333).

  - cifs: Fix to use kmem_cache_free() instead of kfree()
    (bsc#1144333).

  - cifs: Fix trace command logging for SMB2 reads and
    writes (bsc#1144333).

  - cifs: fix typo in cifs_dbg (bsc#1144333).

  - cifs: fix typo in debug message with struct field
    ia_valid (bsc#1144333).

  - cifs: fix uninitialized ptr deref in smb2 signing
    (bsc#1144333).

  - cifs: Fix use-after-free in SMB2_read (bsc#1144333).

  - cifs: Fix use-after-free in SMB2_write (bsc#1144333).

  - cifs: Fix use after free of a mid_q_entry (bsc#1112903,
    bsc#1144333).

  - cifs: fix use-after-free of the lease keys
    (bsc#1144333).

  - cifs: Fix validation of signed data in smb2
    (bsc#1144333).

  - cifs: Fix validation of signed data in smb3+
    (bsc#1144333).

  - cifs: fix wrapping bugs in num_entries() (bsc#1051510,
    bsc#1144333).

  - cifs: flush before set-info if we have writeable handles
    (bsc#1144333).

  - cifs: For SMB2 security informaion query, check for
    minimum sized security descriptor instead of sizeof
    FileAllInformation class (bsc#1051510, bsc#1144333).

  - cifs: handle large EA requests more gracefully in smb2+
    (bsc#1144333).

  - cifs: handle netapp error codes (bsc#1136261).

  - cifs: hide unused functions (bsc#1051510, bsc#1144333).

  - cifs: implement v3.11 preauth integrity (bsc#1051510,
    bsc#1144333).

  - cifs: In Kconfig CONFIG_CIFS_POSIX needs depends on
    legacy (insecure cifs) (bsc#1144333).

  - cifs: integer overflow in in SMB2_ioctl() (bsc#1051510,
    bsc#1144333).

  - cifs: Introduce helper function to get page offset and
    length in smb_rqst (bsc#1144333).

  - cifs: Introduce offset for the 1st page in data transfer
    structures (bsc#1144333).

  - cifs: invalidate cache when we truncate a file
    (bsc#1051510, bsc#1144333).

  - cifs: keep FileInfo handle live during oplock break
    (bsc#1106284, bsc#1131565, bsc#1144333).

  - cifs: limit amount of data we request for xattrs to
    CIFSMaxBufSize (bsc#1144333).

  - cifs: Limit memory used by lock request calls to a page
    (bsc#1144333).

  - cifs_lookup(): cifs_get_inode_...() never returns 0 with
    *inode left NULL (bsc#1144333).

  - cifs_lookup(): switch to d_splice_alias() (bsc#1144333).

  - cifs: make arrays static const, reduces object code size
    (bsc#1144333).

  - cifs: Make devname param optional in
    cifs_compose_mount_options() (bsc#1144333).

  - cifs: make IPC a regular tcon (bsc#1071306,
    bsc#1144333).

  - cifs: make minor clarifications to module params for
    cifs.ko (bsc#1144333).

  - cifs: make mknod() an smb_version_op (bsc#1144333).

  - cifs: make 'nodfs' mount opt a superblock flag
    (bsc#1051510, bsc#1144333).

  - cifs: make rmdir() use compounding (bsc#1144333).

  - cifs: make smb_send_rqst take an array of requests
    (bsc#1144333).

  - cifs: Make sure all data pages are signed correctly
    (bsc#1144333).

  - cifs: Make use of DFS cache to get new DFS referrals
    (bsc#1144333).

  - cifs: Mask off signals when sending SMB packets
    (bsc#1144333).

  - cifs: minor clarification in comments (bsc#1144333).

  - cifs: Minor Kconfig clarification (bsc#1144333).

  - cifs: minor updates to module description for cifs.ko
    (bsc#1144333).

  - cifs: Move credit processing to mid callbacks for SMB3
    (bsc#1144333).

  - cifs: move default port definitions to cifsglob.h
    (bsc#1144333).

  - cifs: move large array from stack to heap (bsc#1144333).

  - cifs: Move open file handling to writepages
    (bsc#1144333).

  - cifs: Move unlocking pages from wdata_send_pages()
    (bsc#1144333).

  - cifs: OFD locks do not conflict with eachothers
    (bsc#1051510, bsc#1144333).

  - cifs: Only free DFS target list if we actually got one
    (bsc#1144333).

  - cifs: Only send SMB2_NEGOTIATE command on new TCP
    connections (bsc#1144333).

  - cifs: only wake the thread for the very last PDU in a
    compound (bsc#1144333).

  - cifs: parse and store info on iface queries
    (bsc#1144333).

  - cifs: pass flags down into wait_for_free_credits()
    (bsc#1144333).

  - cifs: Pass page offset for calculating signature
    (bsc#1144333).

  - cifs: Pass page offset for encrypting (bsc#1144333).

  - cifs: pass page offsets on SMB1 read/write
    (bsc#1144333).

  - cifs: prevent integer overflow in nxt_dir_entry()
    (bsc#1051510, bsc#1144333).

  - cifs: prevent starvation in wait_for_free_credits for
    multi-credit requests (bsc#1144333).

  - cifs: print CIFSMaxBufSize as part of
    /proc/fs/cifs/DebugData (bsc#1144333).

  - cifs: Print message when attempting a mount
    (bsc#1144333).

  - cifs: Properly handle auto disabling of serverino option
    (bsc#1144333).

  - cifs: protect against server returning invalid file
    system block size (bsc#1144333).

  - cifs: prototype declaration and definition for smb 2 - 3
    and cifsacl mount options (bsc#1051510, bsc#1144333).

  - cifs: prototype declaration and definition to set acl
    for smb 2 - 3 and cifsacl mount options (bsc#1051510,
    bsc#1144333).

  - cifs: push rfc1002 generation down the stack
    (bsc#1144333).

  - cifs: read overflow in is_valid_oplock_break()
    (bsc#1144333).

  - cifs: Reconnect expired SMB sessions (bnc#1060662).

  - cifs: refactor and clean up arguments in the reparse
    point parsing (bsc#1144333).

  - cifs: refactor crypto shash/sdesc allocation&free
    (bsc#1051510, bsc#1144333).

  - cifs: Refactor out cifs_mount() (bsc#1144333).

  - cifs: release auth_key.response for reconnect
    (bsc#1085536, bsc#1144333).

  - cifs: release cifs root_cred after exit_cifs
    (bsc#1085536, bsc#1144333).

  - cifs: remove coverity warning in calc_lanman_hash
    (bsc#1144333).

  - cifs: Remove custom credit adjustments for SMB2 async IO
    (bsc#1144333).

  - cifs: remove header_preamble_size where it is always 0
    (bsc#1144333).

  - cifs: remove redundant duplicated assignment of pointer
    'node' (bsc#1144333).

  - cifs: remove rfc1002 hardcoded constants from
    cifs_discard_remaining_data() (bsc#1144333).

  - cifs: remove rfc1002 header from all SMB2 response
    structures (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_close_req
    (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_create_req
    (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_echo_req
    (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_flush_req
    (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_ioctl_req
    (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_lease_ack
    (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_lock_req
    (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_logoff_req
    (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_negotiate_req
    (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_oplock_break we
    get from server (bsc#1144333).

  - cifs: remove rfc1002 header from
    smb2_query_directory_req (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_query_info_req
    (bsc#1144333).

  - cifs: remove rfc1002 header from smb2 read/write
    requests (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_sess_setup_req
    (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_set_info_req
    (bsc#1144333).

  - cifs: remove rfc1002 header from smb2_tree_connect_req
    (bsc#1144333).

  - cifs: remove rfc1002 header from
    smb2_tree_disconnect_req (bsc#1144333).

  - cifs: remove set but not used variable 'cifs_sb'
    (bsc#1144333).

  - cifs: remove set but not used variable 'sep'
    (bsc#1144333).

  - cifs: remove set but not used variable 'server'
    (bsc#1144333).

  - cifs: remove set but not used variable 'smb_buf'
    (bsc#1144333).

  - cifs: remove small_smb2_init (bsc#1144333).

  - cifs: remove smb2_send_recv() (bsc#1144333).

  - cifs: remove struct smb2_hdr (bsc#1144333).

  - cifs: remove struct smb2_oplock_break_rsp (bsc#1144333).

  - cifs: remove the is_falloc argument to SMB2_set_eof
    (bsc#1144333).

  - cifs: remove unused stats (bsc#1144333).

  - cifs: remove unused value pointed out by Coverity
    (bsc#1144333).

  - cifs: remove unused variable from SMB2_read
    (bsc#1144333).

  - cifs: rename and clarify CIFS_ASYNC_OP and CIFS_NO_RESP
    (bsc#1144333).

  - cifs: Reopen file before get SMB2 MTU credits for async
    IO (bsc#1144333).

  - cifs: replace a 4 with
    server->vals->header_preamble_size (bsc#1144333).

  - cifs: replace snprintf with scnprintf (bsc#1144333).

  - cifs: Respect reconnect in MTU credits calculations
    (bsc#1144333).

  - cifs: Respect reconnect in non-MTU credits calculations
    (bsc#1144333).

  - cifs: Respect SMB2 hdr preamble size in read responses
    (bsc#1144333).

  - cifs: return correct errors when pinning memory failed
    for direct I/O (bsc#1144333).

  - cifs: Return -EAGAIN instead of -ENOTSOCK (bsc#1144333).

  - cifs: return -ENODATA when deleting an xattr that does
    not exist (bsc#1144333).

  - cifs: Return error code when getting file handle for
    writeback (bsc#1144333).

  - cifs: return error on invalid value written to cifsFYI
    (bsc#1144333).

  - cifs: Save TTL value when parsing DFS referrals
    (bsc#1144333).

  - cifs: Select all required crypto modules (bsc#1085536,
    bsc#1144333).

  - cifs: set mapping error when page writeback fails in
    writepage or launder_pages (bsc#1144333).

  - cifs: set oparms.create_options rather than or'ing in
    CREATE_OPEN_BACKUP_INTENT (bsc#1144333).

  - cifs: Set reconnect instance to one initially
    (bsc#1144333).

  - cifs: set *resp_buf_type to NO_BUFFER on error
    (bsc#1144333).

  - cifs: Show locallease in /proc/mounts for cifs shares
    mounted with locallease feature (bsc#1144333).

  - cifs: show 'soft' in the mount options for hard mounts
    (bsc#1144333).

  - cifs: show the w bit for writeable /proc/fs/cifs/* files
    (bsc#1144333).

  - cifs: silence compiler warnings showing up with
    gcc-8.0.0 (bsc#1090734, bsc#1144333).

  - cifs: Silence uninitialized variable warning
    (bsc#1144333).

  - cifs: simple stats should always be enabled
    (bsc#1144333).

  - cifs: simplify code by removing CONFIG_CIFS_ACL ifdef
    (bsc#1144333). - Update config files.

  - cifs: simplify how we handle credits in
    compound_send_recv() (bsc#1144333).

  - cifs: Skip any trailing backslashes from UNC
    (bsc#1144333).

  - cifs: smb2 commands can not be negative, remove
    confusing check (bsc#1144333).

  - cifs: smb2ops: Fix listxattr() when there are no EAs
    (bsc#1051510, bsc#1144333).

  - cifs: smb2ops: Fix NULL check in smb2_query_symlink
    (bsc#1144333).

  - cifs: smb2pdu: Fix potential NULL pointer dereference
    (bsc#1144333).

  - cifs: smbd: Add parameter rdata to smb2_new_read_req
    (bsc#1144333).

  - cifs: smbd: Add rdma mount option (bsc#1144333).

  - cifs: smbd: Add SMB Direct debug counters (bsc#1144333).

  - cifs: smbd: Add SMB Direct protocol initial values and
    constants (bsc#1144333).

  - cifs: smbd: Avoid allocating iov on the stack
    (bsc#1144333).

  - cifs: smbd: avoid reconnect lockup (bsc#1144333).

  - cifs: smbd: Check for iov length on sending the last iov
    (bsc#1144333).

  - cifs: smbd: depend on INFINIBAND_ADDR_TRANS
    (bsc#1144333).

  - cifs: smbd: Disable signing on SMB direct transport
    (bsc#1144333).

  - cifs: smbd: disconnect transport on RDMA errors
    (bsc#1144333).

  - cifs: smbd: Do not call ib_dereg_mr on invalidated
    memory registration (bsc#1144333).

  - cifs: smbd: Do not destroy transport on RDMA disconnect
    (bsc#1144333).

  - cifs: smbd: Do not use RDMA read/write when signing is
    used (bsc#1144333).

  - cifs: smbd: Dump SMB packet when configured
    (bsc#1144333).

  - cifs: smbd: Enable signing with smbdirect (bsc#1144333).

  - cifs: smbd: Establish SMB Direct connection
    (bsc#1144333).

  - cifs: smbd: export protocol initial values
    (bsc#1144333).

  - cifs: smbd: fix spelling mistake: faield and legnth
    (bsc#1144333).

  - cifs: smbd: Fix the definition for
    SMB2_CHANNEL_RDMA_V1_INVALIDATE (bsc#1144333).

  - cifs: smbd: Implement function to create a SMB Direct
    connection (bsc#1144333).

  - cifs: smbd: Implement function to destroy a SMB Direct
    connection (bsc#1144333).

  - cifs: smbd: Implement function to receive data via RDMA
    receive (bsc#1144333).

  - cifs: smbd: Implement function to reconnect to a SMB
    Direct transport (bsc#1144333).

  - cifs: smbd: Implement function to send data via RDMA
    send (bsc#1144333).

  - cifs: smbd: Implement RDMA memory registration
    (bsc#1144333).

  - cifs: smbd: Indicate to retry on transport sending
    failure (bsc#1144333).

  - cifs: smbd: Read correct returned data length for RDMA
    write (SMB read) I/O (bsc#1144333).

  - cifs: smbd: Retry on memory registration failure
    (bsc#1144333).

  - cifs: smbd: Return EINTR when interrupted (bsc#1144333).

  - cifs: smbd: Set SMB Direct maximum read or write size
    for I/O (bsc#1144333).

  - cifs: smbd: _smbd_get_connection() can be static
    (bsc#1144333).

  - cifs: smbd: Support page offset in memory registration
    (bsc#1144333).

  - cifs: smbd: Support page offset in RDMA recv
    (bsc#1144333).

  - cifs: smbd: Support page offset in RDMA send
    (bsc#1144333).

  - cifs: smbd: take an array of reqeusts when sending upper
    layer data (bsc#1144333).

  - cifs: smbd: Upper layer connects to SMBDirect session
    (bsc#1144333).

  - cifs: smbd: Upper layer destroys SMB Direct session on
    shutdown or umount (bsc#1144333).

  - cifs: smbd: Upper layer performs SMB read via RDMA write
    through memory registration (bsc#1144333).

  - cifs: smbd: Upper layer performs SMB write via RDMA read
    through memory registration (bsc#1144333).

  - cifs: smbd: Upper layer receives data via RDMA receive
    (bsc#1144333).

  - cifs: smbd: Upper layer reconnects to SMB Direct session
    (bsc#1144333).

  - cifs: smbd: Upper layer sends data via RDMA send
    (bsc#1144333).

  - cifs:smbd Use the correct DMA direction when sending
    data (bsc#1144333).

  - cifs:smbd When reconnecting to server, call
    smbd_destroy() after all MIDs have been called
    (bsc#1144333).

  - cifs: smbd: work around gcc -Wmaybe-uninitialized
    warning (bsc#1144333).

  - cifs: start DFS cache refresher in cifs_mount()
    (bsc#1144333).

  - cifs: store the leaseKey in the fid on SMB2_open
    (bsc#1051510, bsc#1144333).

  - cifs: suppress some implicit-fallthrough warnings
    (bsc#1144333).

  - cifs: track writepages in vfs operation counters
    (bsc#1144333).

  - cifs: Try to acquire credits at once for compound
    requests (bsc#1144333).

  - cifs: update calc_size to take a server argument
    (bsc#1144333).

  - cifs: update init_sg, crypt_message to take an array of
    rqst (bsc#1144333).

  - cifs: update internal module number (bsc#1144333).

  - cifs: update internal module version number
    (bsc#1144333).

  - cifs: update internal module version number for cifs.ko
    to 2.12 (bsc#1144333).

  - cifs: update internal module version number for cifs.ko
    to 2.14 (bsc#1144333).

  - cifs: update module internal version number
    (bsc#1144333).

  - cifs: update multiplex loop to handle compounded
    responses (bsc#1144333).

  - cifs: update receive_encrypted_standard to handle
    compounded responses (bsc#1144333).

  - cifs: update smb2_calc_size to use smb2_sync_hdr instead
    of smb2_hdr (bsc#1144333).

  - cifs: update smb2_check_message to handle PDUs without a
    4 byte length header (bsc#1144333).

  - cifs: update smb2_queryfs() to use compounding
    (bsc#1144333).

  - cifs: update __smb_send_rqst() to take an array of
    requests (bsc#1144333).

  - cifs: use a compound for setting an xattr (bsc#1144333).

  - cifs: use a refcount to protect open/closing the cached
    file handle (bsc#1144333).

  - cifs: use correct format characters (bsc#1144333).

  - cifs: Use correct packet length in SMB2_TRANSFORM header
    (bsc#1144333).

  - cifs: Use GFP_ATOMIC when a lock is held in cifs_mount()
    (bsc#1144333).

  - cifs: Use kmemdup in SMB2_ioctl_init() (bsc#1144333).

  - cifs: Use kmemdup rather than duplicating its
    implementation in smb311_posix_mkdir() (bsc#1144333).

  - cifs: Use kzfree() to free password (bsc#1144333).

  - cifs: Use offset when reading pages (bsc#1144333).

  - cifs: Use smb 2 - 3 and cifsacl mount options getacl
    functions (bsc#1051510, bsc#1144333).

  - cifs: Use smb 2 - 3 and cifsacl mount options setacl
    function (bsc#1051510, bsc#1144333).

  - cifs: use tcon_ipc instead of use_ipc parameter of
    SMB2_ioctl (bsc#1071306, bsc#1144333).

  - cifs: use the correct length when pinning memory for
    direct I/O for write (bsc#1144333).

  - cifs: Use ULL suffix for 64-bit constant (bsc#1051510,
    bsc#1144333).

  - cifs: wait_for_free_credits() make it possible to wait
    for >=1 credits (bsc#1144333).

  - cifs: we can not use small padding iovs together with
    encryption (bsc#1144333).

  - cifs: When sending data on socket, pass the correct page
    offset (bsc#1144333).

  - cifs: zero-range does not require the file is sparse
    (bsc#1144333).

  - cifs: zero sensitive data when freeing (bsc#1087092,
    bsc#1144333).

  - Cleanup some minor endian issues in smb3 rdma
    (bsc#1144333).

  - clk: add clk_bulk_get accessories (bsc#1144813).

  - clk: bcm2835: remove pllb (jsc#SLE-7294).

  - clk: bcm283x: add driver interfacing with Raspberry Pi's
    firmware (jsc#SLE-7294).

  - clk: bulk: silently error out on EPROBE_DEFER
    (bsc#1144718,bsc#1144813).

  - clk: Export clk_bulk_prepare() (bsc#1144813).

  - clk: raspberrypi: register platform device for
    raspberrypi-cpufreq (jsc#SLE-7294).

  - clk: renesas: cpg-mssr: Fix reset control race condition
    (bsc#1051510).

  - clk: rockchip: Add 1.6GHz PLL rate for rk3399
    (bsc#1144718,bsc#1144813).

  - clk: rockchip: assign correct id for pclk_ddr and
    hclk_sd in rk3399 (bsc#1144718,bsc#1144813).

  - compat_ioctl: pppoe: fix PPPOEIOCSFWD handling
    (bsc#1051510).

  - config: arm64: Remove CONFIG_ARM64_MODULE_CMODEL_LARGE
    Option removed by patches in bsc#1148219

  - coredump: split pipe command whitespace before expanding
    template (bsc#1051510).

  - cpufreq: add driver for Raspberry Pi (jsc#SLE-7294).

  - cpufreq: dt: Try freeing static OPPs only if we have
    added them (jsc#SLE-7294).

  - cpu/speculation: Warn on unsupported mitigations=
    parameter (bsc#1114279).

  - crypto: ccp - Add support for valid authsize values less
    than 16 (bsc#1051510).

  - crypto: ccp - Fix oops by properly managing allocated
    structures (bsc#1051510).

  - crypto: ccp - Ignore tag length when decrypting GCM
    ciphertext (bsc#1051510).

  - crypto: ccp - Ignore unconfigured CCP device on
    suspend/resume (bnc#1145934).

  - crypto: ccp - Validate buffer lengths for copy
    operations (bsc#1051510).

  - crypto: virtio - Read crypto services and algorithm
    masks (jsc#SLE-5844 jsc#SLE-6331 FATE#327377 bsc#1145446
    LTC#175307).

  - crypto: virtio - Register an algo only if it's supported
    (jsc#SLE-5844 jsc#SLE-6331 FATE#327377 bsc#1145446
    LTC#175307).

  - cx82310_eth: fix a memory leak bug (bsc#1051510).

  - dax: dax_layout_busy_page() should not unmap cow pages
    (bsc#1148698).

  - devres: always use dev_name() in devm_ioremap_resource()
    (git fixes).

  - dfs_cache: fix a wrong use of kfree in flush_cache_ent()
    (bsc#1144333).

  - dmaengine: rcar-dmac: Reject zero-length slave DMA
    requests (bsc#1051510).

  - dm btree: fix order of block initialization in
    btree_split_beneath (git fixes).

  - dm bufio: fix deadlock with loop device (git fixes).

  - dm cache metadata: Fix loading discard bitset (git
    fixes).

  - dm crypt: do not overallocate the integrity tag space
    (git fixes).

  - dm crypt: fix parsing of extended IV arguments (git
    fixes).

  - dm delay: fix a crash when invalid device is specified
    (git fixes).

  - dm: fix to_sector() for 32bit (git fixes).

  - dm integrity: change memcmp to strncmp in
    dm_integrity_ctr (git fixes).

  - dm integrity: correctly calculate the size of metadata
    area (git fixes).

  - dm integrity: fix a crash due to BUG_ON in
    __journal_read_write() (git fixes).

  - dm integrity: fix deadlock with overlapping I/O (git
    fixes).

  - dm integrity: limit the rate of error messages (git
    fixes).

  - dm kcopyd: always complete failed jobs (git fixes).

  - dm log writes: make sure super sector log updates are
    written in order (git fixes).

  - dm raid: add missing cleanup in raid_ctr() (git fixes).

  - dm: revert 8f50e358153d ('dm: limit the max bio size as
    BIO_MAX_PAGES * PAGE_SIZE') (git fixes).

  - dm space map metadata: fix missing store of apply_bops()
    return value (git fixes).

  - dm table: fix invalid memory accesses with too high
    sector number (git fixes).

  - dm table: propagate BDI_CAP_STABLE_WRITES to fix
    sporadic checksum errors (git fixes).

  - dm thin: fix bug where bio that overwrites thin block
    ignores FUA (git fixes).

  - dm thin: fix passdown_double_checking_shared_status()
    (git fixes).

  - dm zoned: fix potential NULL dereference in
    dmz_do_reclaim() (git fixes).

  - dm zoned: Fix zone report handling (git fixes).

  - dm zoned: fix zone state management race (git fixes).

  - dm zoned: improve error handling in i/o map code (git
    fixes).

  - dm zoned: improve error handling in reclaim (git fixes).

  - dm zoned: properly handle backing device failure (git
    fixes).

  - dm zoned: Silence a static checker warning (git fixes).

  - Documentation: Update Documentation for
    iommu.passthrough (bsc#1136039).

  - Do not log confusing message on reconnect by default
    (bsc#1129664, bsc#1144333).

  - Do not log expected error on DFS referral request
    (bsc#1051510, bsc#1144333).

  - drivers/pps/pps.c: clear offset flags in PPS_SETPARAMS
    ioctl (bsc#1051510).

  - drivers/rapidio/devices/rio_mport_cdev.c: NUL terminate
    some strings (bsc#1051510).

  - drm/amd/display: Fix dc_create failure handling and 666
    color depths (bsc#1111666).

  - drm/amd/display: Increase size of audios array
    (bsc#1111666).

  - drm/amd/display: num of sw i2c/aux engines less than num
    of connectors (bsc#1145946).

  - drm/amd/display: Only enable audio if speaker allocation
    exists (bsc#1111666).

  - drm/amd/display: Remove redundant non-zero and overflow
    check (bsc#1145946).

  - drm/amd/display: use encoder's engine id to find matched
    free audio device (bsc#1111666).

  - drm/amd/display: Wait for backlight programming
    completion in set backlight level (bsc#1111666).

  - drm/amdgpu: Add APTX quirk for Dell Latitude 5495
    (bsc#1142635)

  - drm/amdgpu: added support 2nd UVD instance
    (bsc#1143331).

  - drm/amdgpu:change VEGA booting with firmware loaded by
    PSP (bsc#1143331).

  - drm/amdgpu: fix a potential information leaking bug
    (bsc#1111666).

  - drm/amdgpu/psp: move psp version specific function
    pointers to (bsc#1135642)

  - drm/bridge: lvds-encoder: Fix build error while
    CONFIG_DRM_KMS_HELPER=m (bsc#1111666).

  - drm/crc-debugfs: Also sprinkle irqrestore over early
    exits (bsc#1051510).

  - drm/edid: parse CEA blocks embedded in DisplayID
    (bsc#1111666).

  - drm/etnaviv: add missing failure path to destroy
    suballoc (bsc#1135642)

  - drm/exynos: fix missing decrement of retry counter
    (bsc#1111666).

  - drm/i915: Do not deballoon unused ggtt drm_mm_node in
    linux guest (bsc#1142635)

  - drm/i915: Fix GEN8_MCR_SELECTOR programming
    (bsc#1111666).

  - drm/i915: Fix HW readout for crtc_clock in HDMI mode
    (bsc#1111666).

  - drm/i915: Fix the TBT AUX power well enabling
    (bsc#1111666).

  - drm/i915: Fix wrong escape clock divisor init for GLK
    (bsc#1051510).

  - drm/i915: Fix wrong escape clock divisor init for GLK
    (bsc#1142635)

  - drm/i915/gvt: fix incorrect cache entry for guest page
    mapping (bsc#1111666).

  - drm/i915/perf: ensure we keep a reference on the driver
    (bsc#1051510).

  - drm/i915/perf: ensure we keep a reference on the driver
    (bsc#1142635)

  - drm/i915/perf: fix ICL perf register offsets
    (bsc#1111666).

  - drm/i915: Restore relaxed padding
    (OCL_OOB_SUPPRES_ENABLE) for skl+ (bsc#1142635)

  - drm/i915/userptr: Acquire the page lock around
    set_page_dirty() (bsc#1051510).

  - drm/imx: notify drm core before sending event during
    crtc disable (bsc#1135642)

  - drm/imx: only send event on crtc disable if kept
    disabled (bsc#1135642)

  - drm/mediatek: call drm_atomic_helper_shutdown() when
    unbinding driver (bsc#1135642)

  - drm/mediatek: call mtk_dsi_stop() after
    mtk_drm_crtc_atomic_disable() (bsc#1135642)

  - drm/mediatek: clear num_pipes when unbind driver
    (bsc#1135642)

  - drm/mediatek: fix unbind functions (bsc#1135642)

  - drm/mediatek: mtk_drm_drv.c: Add of_node_put() before
    goto (bsc#1111666).

  - drm/mediatek: mtk_drm_drv.c: Add of_node_put() before
    goto (bsc#1142635)

  - drm/mediatek: unbind components in mtk_drm_unbind()
    (bsc#1135642)

  - drm/mediatek: use correct device to import PRIME buffers
    (bsc#1111666).

  - drm/mediatek: use correct device to import PRIME buffers
    (bsc#1142635)

  - drm: msm: Fix add_gpu_components (bsc#1051510).

  - drm/msm/mdp5: Fix mdp5_cfg_init error return
    (bsc#1142635)

  - drm/nouveau: Do not retry infinitely when receiving no
    data on i2c (bsc#1142635)

  - drm/nouveau: fix memory leak in nouveau_conn_reset()
    (bsc#1051510).

  - drm/rockchip: Suspend DP late (bsc#1051510).

  - drm/rockchip: Suspend DP late (bsc#1142635)

  - drm: silence variable 'conn' set but not used
    (bsc#1051510).

  - drm/udl: introduce a macro to convert dev to udl.
    (bsc#1113722)

  - drm/udl: move to embedding drm device inside udl device.
    (bsc#1113722)

  - drm/vmwgfx: fix a warning due to missing dma_parms
    (bsc#1135642)

  - drm/vmwgfx: fix memory leak when too many retries have
    occurred (bsc#1051510).

  - drm/vmwgfx: Use the backdoor port if the HB port is not
    available (bsc#1135642)

  - Drop an ASoC fix that was reverted in 4.14.y stable

  - EDAC/amd64: Add Family 17h Model 30h PCI IDs
    (bsc#1112178).

  - EDAC, amd64: Add Family 17h, models 10h-2fh support
    (bsc#1112178).

  - EDAC/amd64: Adjust printed chip select sizes when
    interleaved (bsc#1131489).

  - EDAC/amd64: Cache secondary Chip Select registers
    (bsc#1131489).

  - EDAC/amd64: Decode syndrome before translating address
    (bsc#1131489).

  - EDAC/amd64: Find Chip Select memory size using Address
    Mask (bsc#1131489).

  - EDAC/amd64: Initialize DIMM info for systems with more
    than two channels (bsc#1131489).

  - EDAC/amd64: Recognize DRAM device type ECC capability
    (bsc#1131489).

  - EDAC/amd64: Recognize x16 symbol size (bsc#1131489).

  - EDAC/amd64: Set maximum channel layer size depending on
    family (bsc#1131489).

  - EDAC/amd64: Support asymmetric dual-rank DIMMs
    (bsc#1131489).

  - EDAC/amd64: Support more than two controllers for chip
    selects handling (bsc#1131489).

  - EDAC/amd64: Support more than two Unified Memory
    Controllers (bsc#1131489).

  - EDAC/amd64: Use a macro for iterating over Unified
    Memory Controllers (bsc#1131489).

  - ehea: Fix a copy-paste err in ehea_init_port_res
    (bsc#1051510).

  - ext4: use jbd2_inode dirty range scoping (bsc#1148616).

  - firmware: raspberrypi: register clk device
    (jsc#SLE-7294).

  - Fixed https://bugzilla.kernel.org/show_bug.cgi?id=202935
    allow write on the same file (bsc#1144333).

  - Fix encryption labels and lengths for SMB3.1.1
    (bsc#1085536, bsc#1144333).

  - fix incorrect error code mapping for OBJECTID_NOT_FOUND
    (bsc#1144333).

  - Fix match_server check to allow for auto dialect
    negotiate (bsc#1144333).

  - Fix SMB3.1.1 guest authentication to Samba (bsc#1085536,
    bsc#1144333).

  - fix smb3-encryption breakage when CONFIG_DEBUG_SG=y
    (bsc#1051510, bsc#1144333).

  - fix struct ufs_req removal of unused field (git-fixes).

  - Fix warning messages when mounting to older servers
    (bsc#1144333).

  - fs/cifs/cifsacl.c Fixes typo in a comment (bsc#1144333).

  - fs: cifs: cifsssmb: Change return type of
    convert_ace_to_cifs_ace (bsc#1144333).

  - fs/cifs: do not translate SFM_SLASH (U+F026) to
    backslash (bsc#1144333).

  - fs: cifs: Drop unlikely before IS_ERR(_OR_NULL)
    (bsc#1144333).

  - fs/cifs: fix uninitialised variable warnings
    (bsc#1144333).

  - fs: cifs: Kconfig: pedantic formatting (bsc#1144333).

  - fs: cifs: Replace _free_xid call in cifs_root_iget
    function (bsc#1144333).

  - fs/cifs: require sha512 (bsc#1051510, bsc#1144333).

  - fs/cifs: Simplify ib_post_(send|recv|srq_recv)() calls
    (bsc#1144333).

  - fs/cifs/smb2pdu.c: fix buffer free in SMB2_ioctl_free
    (bsc#1144333).

  - fs/cifs: suppress a string overflow warning
    (bsc#1144333).

  - fs/*/Kconfig: drop links to 404-compliant
    http://acl.bestbits.at (bsc#1144333).

  - fsl/fman: Use GFP_ATOMIC in
    (memac,tgec)_add_hash_mac_address() (bsc#1051510).

  - fs/xfs: Fix return code of xfs_break_leased_layouts()
    (bsc#1148031).

  - fs: xfs: xfs_log: Do not use KM_MAYFAIL at
    xfs_log_reserve() (bsc#1148033).

  - ftrace: Check for empty hash and comment the race with
    registering probes (bsc#1149418).

  - ftrace: Check for successful allocation of hash
    (bsc#1149424).

  - ftrace: Fix NULL pointer dereference in t_probe_next()
    (bsc#1149413).

  - gpio: Fix build error of function redefinition
    (bsc#1051510).

  - gpio: gpio-omap: add check for off wake capable gpios
    (bsc#1051510).

  - gpiolib: fix incorrect IRQ requesting of an active-low
    lineevent (bsc#1051510).

  - gpiolib: never report open-drain/source lines as 'input'
    to user-space (bsc#1051510).

  - gpio: mxs: Get rid of external API call (bsc#1051510).

  - gpio: pxa: handle corner case of unprobed device
    (bsc#1051510).

  - gpu: ipu-v3: ipu-ic: Fix saturation bit offset in TPMEM
    (bsc#1142635)

  - HID: Add 044f:b320 ThrustMaster, Inc. 2 in 1 DT
    (bsc#1051510).

  - HID: Add quirk for HP X1200 PIXART OEM mouse
    (bsc#1051510).

  - HID: cp2112: prevent sleeping function called from
    invalid context (bsc#1051510).

  - HID: hiddev: avoid opening a disconnected device
    (bsc#1051510).

  - HID: hiddev: do cleanup in failure of opening a device
    (bsc#1051510).

  - HID: holtek: test for sanity of intfdata (bsc#1051510).

  - HID: sony: Fix race condition between rumble and device
    remove (bsc#1051510).

  - HID: wacom: Correct distance scale for 2nd-gen Intuos
    devices (bsc#1142635).

  - HID: wacom: correct misreported EKR ring values
    (bsc#1142635).

  - HID: wacom: fix bit shift for Cintiq Companion 2
    (bsc#1051510).

  - hwmon: (nct7802) Fix wrong detection of in4 presence
    (bsc#1051510).

  - i2c: emev2: avoid race when unregistering slave client
    (bsc#1051510).

  - i2c: piix4: Fix port selection for AMD Family 16h Model
    30h (bsc#1051510).

  - i2c: qup: fixed releasing dma without flush operation
    completion (bsc#1051510).

  - ia64: Get rid of iommu_pass_through (bsc#1136039).

  - IB/mlx5: Fix MR registration flow to use UMR properly
    (bsc#1093205 bsc#1145678).

  - ibmveth: Convert multicast list size for little-endian
    system (bsc#1061843).

  - ibmvnic: Do not process reset during or after device
    removal (bsc#1149652 ltc#179635).

  - ibmvnic: Unmap DMA address of TX descriptor buffers
    after use (bsc#1146351 ltc#180726).

  - igmp: fix memory leak in igmpv3_del_delrec()
    (networking-stable-19_07_25).

  - iio: adc: max9611: Fix misuse of GENMASK macro
    (bsc#1051510).

  - iio: adc: max9611: Fix temperature reading in probe
    (bsc#1051510).

  - Improve security, move default dialect to SMB3 from old
    CIFS (bsc#1051510, bsc#1144333).

  - include/linux/bitops.h: sanitize rotate primitives (git
    fixes).

  - Input: iforce - add sanity checks (bsc#1051510).

  - Input: kbtab - sanity check for endpoint type
    (bsc#1051510).

  - Input: synaptics - enable RMI mode for HP Spectre X360
    (bsc#1051510).

  - intel_th: pci: Add support for another Lewisburg PCH
    (bsc#1051510).

  - intel_th: pci: Add Tiger Lake support (bsc#1051510).

  - iommu: Add helpers to set/get default domain type
    (bsc#1136039).

  - iommu/amd: Add support for X2APIC IOMMU interrupts
    (bsc#1145010).

  - iommu/amd: Fix race in increase_address_space()
    (bsc#1150860).

  - iommu/amd: Flush old domains in kdump kernel
    (bsc#1150861).

  - iommu/amd: Move iommu_init_pci() to .init section
    (bsc#1149105).

  - iommu/amd: Request passthrough mode from IOMMU core
    (bsc#1136039).

  - iommu: Disable passthrough mode when SME is active
    (bsc#1136039).

  - iommu/dma: Handle SG length overflow better
    (bsc#1146084).

  - iommu/iova: Remove stale cached32_node (bsc#1145018).

  - iommu: Print default domain type on boot (bsc#1136039).

  - iommu: Remember when default domain type was set on
    kernel command line (bsc#1136039).

  - iommu: Set default domain type at runtime (bsc#1136039).

  - iommu: Use Functions to set default domain type in
    iommu_set_def_domain_type() (bsc#1136039).

  - iommu/vt-d: Request passthrough mode from IOMMU core
    (bsc#1136039).

  - ipip: validate header length in ipip_tunnel_xmit
    (git-fixes).

  - ipv4: do not set IPv6 only flags to IPv4 addresses
    (networking-stable-19_07_25).

  - irqchip/gic-v2m: Add support for Amazon Graviton variant
    of GICv3+GICv2m (SLE-9332).

  - irqchip/gic-v3-its: fix build warnings (bsc#1144880).

  - ISDN: hfcsusb: checking idx of ep configuration
    (bsc#1051510).

  - isdn: hfcsusb: Fix mISDN driver crash caused by transfer
    buffer on the stack (bsc#1051510).

  - isdn: mISDN: hfcsusb: Fix possible NULL pointer
    dereferences in start_isoc_chain() (bsc#1051510).

  - iversion: add a routine to update a raw value with a
    larger one (bsc#1148133).

  - iwlwifi: dbg: split iwl_fw_error_dump to two functions
    (bsc#1119086).

  - iwlwifi: do not unmap as page memory that was mapped as
    single (bsc#1051510).

  - iwlwifi: fix bad dma handling in page_mem dumping flow
    (bsc#1120902).

  - iwlwifi: fw: use helper to determine whether to dump
    paging (bsc#1106434). Patch needed to be adjusted,
    because our tree does not have the global variable
    IWL_FW_ERROR_DUMP_PAGING

  - iwlwifi: mvm: do not send GEO_TX_POWER_LIMIT on version
    < 41 (bsc#1142635).

  - iwlwifi: mvm: fix an out-of-bound access (bsc#1051510).

  - iwlwifi: mvm: fix version check for GEO_TX_POWER_LIMIT
    support (bsc#1142635).

  - iwlwifi: pcie: do not service an interrupt that was
    masked (bsc#1142635).

  - iwlwifi: pcie: fix ALIVE interrupt handling for gen2
    devices w/o MSI-X (bsc#1142635).

  - ixgbe: fix possible deadlock in ixgbe_service_task()
    (bsc#1113994 FATE#326315 FATE#326317).

  - jbd2: flush_descriptor(): Do not decrease buffer head's
    ref count (bsc#1143843).

  - jbd2: introduce jbd2_inode dirty range scoping
    (bsc#1148616).

  - kABI: Fix kABI for 'struct amd_iommu' (bsc#1145010).

  - kABI: Fix kABI for x86 pci-dma code (bsc#1136039).

  - kabi/severities: Exclude drivers/crypto/ccp/*

  - kabi/severities: match SLE15 entry ordering.

  - kasan: remove redundant initialization of variable
    'real_size' (git fixes).

  - kconfig/[mn]conf: handle backspace (^H) key
    (bsc#1051510).

  - keys: Fix missing NULL pointer check in
    request_key_auth_describe() (bsc#1051510).

  - kvm: Fix leak vCPU's VMCS value into other pCPU
    (bsc#1145388).

  - kvm: LAPIC: Fix pending interrupt in IRR blocked by
    software disable LAPIC (bsc#1145408).

  - kvm: nVMX: allow setting the VMFUNC controls MSR
    (bsc#1145389).

  - kvm: nVMX: do not use dangling shadow VMCS after guest
    reset (bsc#1145390).

  - kvm: nVMX: Remove unnecessary sync_roots from
    handle_invept (bsc#1145391).

  - kvm: nVMX: Use adjusted pin controls for vmcs02
    (bsc#1145392).

  - kvm: PPC: Book3S HV: Fix CR0 setting in TM emulation
    (bsc#1061840).

  - kvm: s390: add debug logging for cpu model subfunctions
    (jsc#SLE-6240 FATE#327380).

  - kvm: s390: add deflate conversion facilty to cpu model
    (jsc#SLE-6240 FATE#327380).

  - kvm: s390: add enhanced sort facilty to cpu model
    (jsc#SLE-6240 FATE#327380).

  - kvm: s390: add MSA9 to cpumodel (jsc#SLE-6240
    FATE#327380).

  - kvm: s390: add vector BCD enhancements facility to
    cpumodel (jsc#SLE-6240 FATE#327380).

  - kvm: s390: add vector enhancements facility 2 to
    cpumodel (jsc#SLE-6240 FATE#327380).

  - kvm: s390: enable MSA9 keywrapping functions depending
    on cpu model (jsc#SLE-6240 FATE#327380).

  - kvm: s390: implement subfunction processor calls
    (jsc#SLE-6240 FATE#327380).

  - kvm: s390: provide query function for instructions
    returning 32 byte (jsc#SLE-6240 FATE#327380).

  - kvm: VMX: Always signal #GP on WRMSR to MSR_IA32_CR_PAT
    with bad value (bsc#1145393).

  - kvm: VMX: check CPUID before allowing read/write of
    IA32_XSS (bsc#1145394).

  - kvm: VMX: Fix handling of #MC that occurs during
    VM-Entry (bsc#1145395).

  - kvm: x86: degrade WARN to pr_warn_ratelimited
    (bsc#1145409).

  - kvm: x86: Do not update RIP or do single-step on
    faulting emulation (bsc#1149104).

  - kvm: x86: fix backward migration with async_PF
    (bsc#1146074).

  - kvm/x86: Move MSR_IA32_ARCH_CAPABILITIES to array
    emulated_msrs (bsc#1134881 bsc#1134882).

  - kvm: X86: Reduce the overhead when lapic_timer_advance
    is disabled (bsc#1149083).

  - kvm: x86: Unconditionally enable irqs in guest context
    (bsc#1145396).

  - kvm: x86/vPMU: refine kvm_pmu err msg when event
    creation failed (bsc#1145397).

  - lan78xx: Fix memory leaks (bsc#1051510).

  - libata: add SG safety checks in SFF pio transfers
    (bsc#1051510).

  - libata: have ata_scsi_rw_xlat() fail invalid passthrough
    requests (bsc#1051510).

  - libceph: add ceph_decode_entity_addr (bsc#1148133
    bsc#1136682).

  - libceph: ADDR2 support for monmap (bsc#1148133
    bsc#1136682).

  - libceph: allow ceph_buffer_put() to receive a NULL
    ceph_buffer (bsc#1148133).

  - libceph: correctly decode ADDR2 addresses in incremental
    OSD maps (bsc#1148133 bsc#1136682).

  - libceph: fix PG split vs OSD (re)connect race
    (bsc#1148133).

  - libceph: fix sa_family just after reading address
    (bsc#1148133 bsc#1136682).

  - libceph: fix unaligned accesses in ceph_entity_addr
    handling (bsc#1136682).

  - libceph: fix watch_item_t decoding to use
    ceph_decode_entity_addr (bsc#1148133 bsc#1136682).

  - libceph: make ceph_pr_addr take an struct
    ceph_entity_addr pointer (bsc#1136682).

  - libceph: rename ceph_encode_addr to
    ceph_encode_banner_addr (bsc#1148133 bsc#1136682).

  - libceph: switch osdmap decoding to use
    ceph_decode_entity_addr (bsc#1148133 bsc#1136682).

  - libceph: turn on CEPH_FEATURE_MSG_ADDR2 (bsc#1148133
    bsc#1136682).

  - libceph: use TYPE_LEGACY for entity addrs instead of
    TYPE_NONE (bsc#1148133 bsc#1136682).

  - libnvdimm/pfn: Store correct value of npfns in namespace
    superblock (bsc#1146381 ltc#180720).

  - liquidio: add cleanup in octeon_setup_iq()
    (bsc#1051510).

  - loop: set PF_MEMALLOC_NOIO for the worker thread (git
    fixes).

  - lpfc: fix 12.4.0.0 GPF at boot (bsc#1148308).

  - mac80211: Correctly set noencrypt for PAE frames
    (bsc#1111666).

  - mac80211: Do not memset RXCB prior to PAE intercept
    (bsc#1111666).

  - mac80211: do not warn about CW params when not using
    them (bsc#1051510).

  - mac80211: do not WARN on short WMM parameters from AP
    (bsc#1051510).

  - mac80211: fix possible memory leak in
    ieee80211_assign_beacon (bsc#1142635).

  - mac80211: fix possible sta leak (bsc#1051510).

  - mac80211_hwsim: Fix possible NULL pointer dereferences
    in hwsim_dump_radio_nl() (bsc#1111666).

  - md: add mddev->pers to avoid potential NULL pointer
    dereference (git fixes).

  - md/raid: raid5 preserve the writeback action after the
    parity check (git fixes).

  - media: au0828: fix null dereference in error path
    (bsc#1051510).

  - media: pvrusb2: use a different format for warnings
    (bsc#1051510).

  - mfd: arizona: Fix undefined behavior (bsc#1051510).

  - mfd: core: Set fwnode for created devices (bsc#1051510).

  - mfd: hi655x-pmic: Fix missing return value check for
    devm_regmap_init_mmio_clk (bsc#1051510).

  - mfd: intel-lpss: Add Intel Comet Lake PCI IDs
    (jsc#SLE-4875).

  - mlxsw: spectrum: Fix error path in
    mlxsw_sp_module_init() (bsc#1112374).

  - mm: add filemap_fdatawait_range_keep_errors()
    (bsc#1148616).

  - mmc: cavium: Add the missing dma unmap when the dma has
    finished (bsc#1051510).

  - mmc: cavium: Set the correct dma max segment size for
    mmc_host (bsc#1051510).

  - mmc: core: Fix init of SD cards reporting an invalid VDD
    range (bsc#1051510).

  - mmc: dw_mmc: Fix occasional hang after tuning on eMMC
    (bsc#1051510).

  - mmc: sdhci-of-at91: add quirk for broken HS200
    (bsc#1051510).

  - mmc: sdhci-pci: Add support for Intel CML
    (jsc#SLE-4875).

  - mmc: sdhci-pci: Add support for Intel ICP
    (jsc#SLE-4875).

  - mmc: sdhci-pci: Fix BYT OCP setting (bsc#1051510).

  - mm: do not stall register_shrinker() (bsc#1104902, VM
    Performance).

  - mm/hmm: fix bad subpage pointer in try_to_unmap_one
    (bsc#1148202, HMM, VM Functionality).

  - mm/hotplug: fix offline undo_isolate_page_range()
    (bsc#1148196, VM Functionality).

  - mm/list_lru.c: fix memory leak in
    __memcg_init_list_lru_node (bsc#1148379, VM
    Functionality).

  - mm/memcontrol.c: fix use after free in mem_cgroup_iter()
    (bsc#1149224, VM Functionality).

  - mm/memory.c: recheck page table entry with page table
    lock held (bsc#1148363, VM Functionality).

  - mm/migrate.c: initialize pud_entry in migrate_vma()
    (bsc#1148198, HMM, VM Functionality).

  - mm/mlock.c: change count_mm_mlocked_page_nr return type
    (bsc#1148527, VM Functionality).

  - mm/mlock.c: mlockall error for flag MCL_ONFAULT
    (bsc#1148527, VM Functionality).

  - mm: move MAP_SYNC to asm-generic/mman-common.h
    (bsc#1148297).

  - mm/page_alloc.c: fix calculation of pgdat->nr_zones
    (bsc#1148192, VM Functionality).

  - mm: page_mapped: do not assume compound page is huge or
    THP (bsc#1148574, VM Functionality).

  - mm, page_owner: handle THP splits correctly
    (bsc#1149197, VM Debugging Functionality).

  - mm/vmalloc: Sync unmappings in __purge_vmap_area_lazy()
    (bsc#1118689).

  - mm/vmscan.c: fix trying to reclaim unevictable LRU page
    (bsc#1149214, VM Functionality).

  - mm, vmscan: do not special-case slab reclaim when
    watermarks are boosted (git fixes (mm/vmscan)).

  - move a few externs to smbdirect.h to eliminate warning
    (bsc#1144333).

  - mpls: fix warning with multi-label encap (bsc#1051510).

  - nbd: replace kill_bdev() with __invalidate_device()
    again (git fixes).

  - Negotiate and save preferred compression algorithms
    (bsc#1144333).

  - net: bcmgenet: use promisc for unsupported filters
    (networking-stable-19_07_25).

  - net: bridge: mcast: fix stale ipv6 hdr pointer when
    handling v6 query (networking-stable-19_07_25).

  - net: bridge: mcast: fix stale nsrcs pointer in
    igmp3/mld2 report handling (networking-stable-19_07_25).

  - net: bridge: stp: do not cache eth dest pointer before
    skb pull (networking-stable-19_07_25).

  - net: dsa: mv88e6xxx: wait after reset deactivation
    (networking-stable-19_07_25).

  - net: ena: add ethtool function for changing io queue
    sizes (bsc#1139020 bsc#1139021).

  - net: ena: add good checksum counter (bsc#1139020
    bsc#1139021).

  - net: ena: add handling of llq max tx burst size
    (bsc#1139020 bsc#1139021).

  - net: ena: add MAX_QUEUES_EXT get feature admin command
    (bsc#1139020 bsc#1139021).

  - net: ena: add newline at the end of pr_err prints
    (bsc#1139020 bsc#1139021).

  - net: ena: add support for changing max_header_size in
    LLQ mode (bsc#1139020 bsc#1139021).

  - net: ena: allow automatic fallback to polling mode
    (bsc#1139020 bsc#1139021).

  - net: ena: allow queue allocation backoff when low on
    memory (bsc#1139020 bsc#1139021).

  - net: ena: arrange ena_probe() function variables in
    reverse christmas tree (bsc#1139020 bsc#1139021).

  - net: ena: enable negotiating larger Rx ring size
    (bsc#1139020 bsc#1139021).

  - net: ena: ethtool: add extra properties retrieval via
    get_priv_flags (bsc#1139020 bsc#1139021).

  - net: ena: Fix bug where ring allocation backoff stopped
    too late (bsc#1139020 bsc#1139021).

  - net: ena: fix ena_com_fill_hash_function()
    implementation (bsc#1139020 bsc#1139021).

  - net: ena: fix: Free napi resources when ena_up() fails
    (bsc#1139020 bsc#1139021).

  - net: ena: fix incorrect test of supported hash function
    (bsc#1139020 bsc#1139021).

  - net: ena: fix: set freed objects to NULL to avoid
    failing future allocations (bsc#1139020 bsc#1139021).

  - net: ena: fix swapped parameters when calling
    ena_com_indirect_table_fill_entry (bsc#1139020
    bsc#1139021).

  - net: ena: gcc 8: fix compilation warning (bsc#1139020
    bsc#1139021).

  - net: ena: improve latency by disabling adaptive
    interrupt moderation by default (bsc#1139020
    bsc#1139021).

  - net: ena: make ethtool show correct current and max
    queue sizes (bsc#1139020 bsc#1139021).

  - net: ena: optimise calculations for CQ doorbell
    (bsc#1139020 bsc#1139021).

  - net: ena: remove inline keyword from functions in *.c
    (bsc#1139020 bsc#1139021).

  - net: ena: replace free_tx/rx_ids union with single
    free_ids field in ena_ring (bsc#1139020 bsc#1139021).

  - net: ena: update driver version from 2.0.3 to 2.1.0
    (bsc#1139020 bsc#1139021).

  - net: ena: use dev_info_once instead of static variable
    (bsc#1139020 bsc#1139021).

  - net: fix bpf_xdp_adjust_head regression for generic-XDP
    (bsc#1109837).

  - net: Fix netdev_WARN_ONCE macro (git-fixes).

  - net: hns3: add a check to pointer in error_detected and
    slot_reset (bsc#1104353 FATE#326415).

  - net: hns3: add all IMP return code (bsc#1104353
    FATE#326415).

  - net: hns3: add aRFS support for PF (bsc#1104353
    FATE#326415).

  - net: hns3: add Asym Pause support to fix autoneg problem
    (bsc#1104353 FATE#326415).

  - net: hns3: add check to number of buffer descriptors
    (bsc#1104353 FATE#326415).

  - net: hns3: add default value for tc_size and tc_offset
    (bsc#1104353 FATE#326415).

  - net: hns3: add exception handling when enable NIC HW
    error interrupts (bsc#1104353 FATE#326415).

  - net: hns3: add handling of two bits in MAC tunnel
    interrupts (bsc#1104353 FATE#326415).

  - net: hns3: add handshake with hardware while doing reset
    (bsc#1104353 FATE#326415).

  - net: hns3: Add missing newline at end of file
    (bsc#1104353 FATE#326415).

  - net: hns3: add opcode about query and clear RAS & MSI-X
    to special opcode (bsc#1104353 FATE#326415).

  - net: hns3: add recovery for the H/W errors occurred
    before the HNS dev initialization (bsc#1104353
    FATE#326415).

  - net: hns3: add some error checking in hclge_tm module
    (bsc#1104353 FATE#326415).

  - net: hns3: add support for dump firmware statistics by
    debugfs (bsc#1104353 FATE#326415).

  - net: hns3: adjust hns3_uninit_phy()'s location in the
    hns3_client_uninit() (bsc#1104353 FATE#326415).

  - net: hns3: bitwise operator should use unsigned type
    (bsc#1104353 FATE#326415).

  - net: hns3: change SSU's buffer allocation according to
    UM (bsc#1104353 FATE#326415).

  - net: hns3: check msg_data before memcpy in
    hclgevf_send_mbx_msg (bsc#1104353 FATE#326415).

  - net: hns3: clear restting state when initializing HW
    device (bsc#1104353 FATE#326415).

  - net: hns3: code optimizaition of
    hclge_handle_hw_ras_error() (bsc#1104353 FATE#326415).

  - net: hns3: delay and separate enabling of NIC and ROCE
    HW errors (bsc#1104353 FATE#326415).

  - net: hns3: delay ring buffer clearing during reset
    (bsc#1104353 FATE#326415).

  - net: hns3: delay setting of reset level for hw errors
    until slot_reset is called (bsc#1104353 FATE#326415).

  - net: hns3: delete the redundant user NIC codes
    (bsc#1104353 FATE#326415).

  - net: hns3: do not configure new VLAN ID into VF VLAN
    table when it's full (bsc#1104353 FATE#326415).

  - net: hns3: enable broadcast promisc mode when
    initializing VF (bsc#1104353 FATE#326415).

  - net: hns3: enable DCB when TC num is one and pfc_en is
    non-zero (bsc#1104353 FATE#326415).

  - net: hns3: extract handling of mpf/pf msi-x errors into
    functions (bsc#1104353 FATE#326415).

  - net: hns3: fix a memory leak issue for
    hclge_map_unmap_ring_to_vf_vector (bsc#1104353
    FATE#326415).

  - net: hns3: fix a statistics issue about l3l4 checksum
    error (bsc#1104353 FATE#326415).

  - net: hns3: fix avoid unnecessary resetting for the H/W
    errors which do not require reset (bsc#1104353
    FATE#326415).

  - net: hns3: fix a -Wformat-nonliteral compile warning
    (bsc#1104353 FATE#326415).

  - net: hns3: fix compile warning without CONFIG_RFS_ACCEL
    (bsc#1104353 FATE#326415).

  - net: hns3: fix dereference of ae_dev before it is null
    checked (bsc#1104353 FATE#326415).

  - net: hns3: fixes wrong place enabling ROCE HW error when
    loading (bsc#1104353 FATE#326415).

  - net: hns3: fix flow control configure issue for fibre
    port (bsc#1104353 FATE#326415).

  - net: hns3: fix for dereferencing before null checking
    (bsc#1104353 FATE#326415).

  - net: hns3: fix for skb leak when doing selftest
    (bsc#1104353 FATE#326415).

  - net: hns3: fix __QUEUE_STATE_STACK_XOFF not cleared
    issue (bsc#1104353 FATE#326415).

  - net: hns3: fix race conditions between reset and module
    loading & unloading (bsc#1104353 FATE#326415).

  - net: hns3: fix some coding style issues (bsc#1104353
    FATE#326415).

  - net: hns3: fix VLAN filter restore issue after reset
    (bsc#1104353 FATE#326415).

  - net: hns3: fix wrong size of mailbox responding data
    (bsc#1104353 FATE#326415).

  - net: hns3: free irq when exit from abnormal branch
    (bsc#1104353 FATE#326415).

  - net: hns3: handle empty unknown interrupt (bsc#1104353
    FATE#326415).

  - net: hns3: initialize CPU reverse mapping (bsc#1104353
    FATE#326415).

  - net: hns3: log detail error info of ROCEE ECC and AXI
    errors (bsc#1104353 FATE#326415).

  - net: hns3: make HW GRO handling compliant with SW GRO
    (bsc#1104353 FATE#326415).

  - net: hns3: modify handling of out of memory in
    hclge_err.c (bsc#1104353 FATE#326415).

  - net: hns3: modify hclge_init_client_instance()
    (bsc#1104353 FATE#326415).

  - net: hns3: modify hclgevf_init_client_instance()
    (bsc#1104353 FATE#326415).

  - net: hns3: optimize the CSQ cmd error handling
    (bsc#1104353 FATE#326415).

  - net: hns3: process H/W errors occurred before HNS dev
    initialization (bsc#1104353 FATE#326415).

  - net: hns3: refactor hns3_get_new_int_gl function
    (bsc#1104353 FATE#326415).

  - net: hns3: refactor PF/VF RSS hash key configuration
    (bsc#1104353 FATE#326415).

  - net: hns3: refine the flow director handle (bsc#1104353
    FATE#326415).

  - net: hns3: remove override_pci_need_reset (bsc#1104353
    FATE#326415).

  - net: hns3: remove redundant core reset (bsc#1104353
    FATE#326415).

  - net: hns3: remove RXD_VLD check in hns3_handle_bdinfo
    (bsc#1104353 FATE#326415).

  - net: hns3: remove setting bit of reset_requests when
    handling mac tunnel interrupts (bsc#1104353
    FATE#326415).

  - net: hns3: remove unused linkmode definition
    (bsc#1104353 FATE#326415).

  - net: hns3: remove VF VLAN filter entry inexistent
    warning print (bsc#1104353 FATE#326415).

  - net: hns3: replace numa_node_id with numa_mem_id for
    buffer reusing (bsc#1104353 FATE#326415).

  - net: hns3: re-schedule reset task while VF reset fail
    (bsc#1104353 FATE#326415).

  - net: hns3: set default value for param 'type' in
    hclgevf_bind_ring_to_vector (bsc#1104353 FATE#326415).

  - net: hns3: set maximum length to resp_data_len for
    exceptional case (bsc#1104353 FATE#326415).

  - net: hns3: set ops to null when unregister ad_dev
    (bsc#1104353 FATE#326415).

  - net: hns3: set the port shaper according to MAC speed
    (bsc#1104353 FATE#326415).

  - net: hns3: small changes for magic numbers (bsc#1104353
    FATE#326415).

  - net: hns3: some changes of MSI-X bits in PPU(RCB)
    (bsc#1104353 FATE#326415).

  - net: hns3: some modifications to simplify and optimize
    code (bsc#1104353 FATE#326415).

  - net: hns3: some variable modification (bsc#1104353
    FATE#326415).

  - net: hns3: stop schedule reset service while unloading
    driver (bsc#1104353 FATE#326415).

  - net: hns3: sync VLAN filter entries when kill VLAN ID
    failed (bsc#1104353 FATE#326415).

  - net: hns3: trigger VF reset if a VF has an
    over_8bd_nfe_err (bsc#1104353 FATE#326415).

  - net: hns3: typo in the name of a constant (bsc#1104353
    FATE#326415).

  - net: hns3: use HCLGE_STATE_NIC_REGISTERED to indicate PF
    NIC client has registered (bsc#1104353 FATE#326415).

  - net: hns3: use HCLGE_STATE_ROCE_REGISTERED to indicate
    PF ROCE client has registered (bsc#1104353 FATE#326415).

  - net: hns3: use HCLGEVF_STATE_NIC_REGISTERED to indicate
    VF NIC client has registered (bsc#1104353 FATE#326415).

  - net: hns3: use macros instead of magic numbers
    (bsc#1104353 FATE#326415).

  - net: hns: add support for vlan TSO (bsc#1104353
    FATE#326415).

  - net/ibmvnic: Fix missing ( in __ibmvnic_reset
    (bsc#1149652 ltc#179635).

  - net/ibmvnic: free reset work of removed device from
    queue (bsc#1149652 ltc#179635).

  - net: Introduce netdev_*_once functions
    (networking-stable-19_07_25).

  - net: make skb_dst_force return true when dst is
    refcounted (networking-stable-19_07_25).

  - net/mlx4_core: Zero out lkey field in SW2HW_MPT fw
    command (bsc#1145678).

  - net/mlx5e: always initialize frag->last_in_page
    (bsc#1103990 FATE#326006).

  - net/mlx5e: IPoIB, Add error path in mlx5_rdma_setup_rn
    (networking-stable-19_07_25).

  - net/mlx5: Fix modify_cq_in alignment (bsc#1103990
    FATE#326006).

  - net: mvpp2: Do not check for 3 consecutive Idle frames
    for 10G links (bsc#1119113 FATE#326472).

  - net: neigh: fix multiple neigh timer scheduling
    (networking-stable-19_07_25).

  - net: openvswitch: fix csum updates for MPLS actions
    (networking-stable-19_07_25).

  - net: phylink: Fix flow control for fixed-link
    (bsc#1119113 FATE#326472).

  - netrom: fix a memory leak in nr_rx_frame()
    (networking-stable-19_07_25).

  - netrom: hold sock when setting skb->destructor
    (networking-stable-19_07_25).

  - net_sched: unset TCQ_F_CAN_BYPASS when adding filters
    (networking-stable-19_07_25).

  - net: sched: verify that q!=NULL before setting q->flags
    (git-fixes).

  - net: usb: pegasus: fix improper read if get_registers()
    fail (bsc#1051510).

  - NFS: Cleanup if nfs_match_client is interrupted
    (bsc#1134291).

  - NFS: Fix a double unlock from nfs_match,get_client
    (bsc#1134291).

  - NFS: Fix the inode request accounting when pages have
    subrequests (bsc#1140012).

  - NFS: make nfs_match_client killable (bsc#1134291).

  - nilfs2: do not use unexported
    cpu_to_le32()/le32_to_cpu() in uapi header (git fixes).

  - (nl,mac)80211: fix interface combinations on crypto
    controlled devices (bsc#1111666).

  - nvme: cancel request synchronously (bsc#1145661).

  - nvme: change locking for the per-subsystem controller
    list (bsc#1142541).

  - nvme-core: Fix extra device_put() call on error path
    (bsc#1142541).

  - nvme-fc: fix module unloads while lports still pending
    (bsc#1150033).

  - nvme: introduce NVME_QUIRK_IGNORE_DEV_SUBNQN
    (bsc#1146938).

  - nvme-multipath: fix ana log nsid lookup when nsid is not
    found (bsc#1141554).

  - nvme-multipath: relax ANA state check (bsc#1123105).

  - nvme-multipath: revalidate nvme_ns_head gendisk in
    nvme_validate_ns (bsc#1120876).

  - nvme: Return BLK_STS_TARGET if the DNR bit is set
    (bsc#1142076).

  - objtool: Add rewind_stack_do_exit() to the noreturn list
    (bsc#1145302).

  - objtool: Support GCC 9 cold subfunction naming scheme
    (bsc#1145300).

  - octeon_mgmt: Fix MIX registers configuration on MTU
    setup (bsc#1051510).

  - PCI: al: Add Amazon Annapurna Labs PCIe host controller
    driver (SLE-9332).

  - PCI: PM/ACPI: Refresh all stale power state data in
    pci_pm_complete() (bsc#1149106).

  - PCI: Restore Resizable BAR size bits correctly for 1MB
    BARs (bsc#1143841).

  - phy: qcom-qusb2: Fix crash if nvmem cell not specified
    (bsc#1051510).

  - phy: renesas: rcar-gen2: Fix memory leak at error paths
    (bsc#1051510).

  - PM / devfreq: rk3399_dmc: do not print error when get
    supply and clk defer (bsc#1144718,bsc#1144813).

  - PM / devfreq: rk3399_dmc: fix spelling mistakes
    (bsc#1144718,bsc#1144813).

  - PM / devfreq: rk3399_dmc: Pass ODT and auto power down
    parameters to TF-A (bsc#1144718,bsc#1144813).

  - PM / devfreq: rk3399_dmc: remove unneeded semicolon
    (bsc#1144718,bsc#1144813).

  - PM / devfreq: rk3399_dmc: remove wait for dcf irq event
    (bsc#1144718,bsc#1144813).

  - PM / devfreq: rockchip-dfi: Move GRF definitions to a
    common place (bsc#1144718,bsc#1144813).

  - PM / OPP: OF: Use pr_debug() instead of pr_err() while
    adding OPP table (jsc#SLE-7294).

  - powerpc/64s: Include cpu header (bsc#1065729).

  - powerpc/64s: support nospectre_v2 cmdline option
    (bsc#1131107).

  - powerpc: Allow flush_(inval_)dcache_range to work across
    ranges >4GB (bsc#1146575 ltc#180764).

  - powerpc/book3s/64: check for NULL pointer in pgd_alloc()
    (FATE#322447, bsc#1078248, git-fixes).

  - powerpc: dump kernel log before carrying out fadump or
    kdump (bsc#1149940 ltc#179958).

  - powerpc/fadump: use kstrtoint to handle sysfs store
    (bsc#1146376).

  - powerpc/fadump: when fadump is supported register the
    fadump sysfs files (bsc#1146352).

  - powerpc/fsl: Add nospectre_v2 command line argument
    (bsc#1131107).

  - powerpc/fsl: Update Spectre v2 reporting (bsc#1131107).

  - powerpc/lib: Fix feature fixup test of external branch
    (bsc#1065729).

  - powerpc/mm: Handle page table allocation failures
    (bsc#1065729).

  - powerpc/nvdimm: Pick nearby online node if the device
    node is not online (bsc#1142685 ltc#179509 FATE#327775).

  - powerpc/perf: Add constraints for power9 l2/l3 bus
    events (bsc#1056686).

  - powerpc/perf: Add mem access events to sysfs
    (FATE#326869, bsc#1124370).

  - powerpc/perf: Cleanup cache_sel bits comment
    (bsc#1056686).

  - powerpc/perf: Fix thresholding counter data for unknown
    type (bsc#1056686).

  - powerpc/perf: Remove PM_BR_CMPL_ALT from power9 event
    list (bsc#1047238, bsc#1056686).

  - powerpc/perf: Remove PM_BR_CMPL_ALT from power9 event
    list (fate#321438, bsc#1047238, bsc#1056686).

  - powerpc/perf: Update perf_regs structure to include SIER
    (bsc#1056686).

  - powerpc/powernv: Flush console before platform error
    reboot (bsc#1149940 ltc#179958).

  - powerpc/powernv/opal-dump : Use IRQ_HANDLED instead of
    numbers in interrupt handler (bsc#1065729).

  - powerpc/powernv: Return for invalid IMC domain
    (bsc1054914, fate#322448, git-fixes).

  - powerpc/powernv: Return for invalid IMC domain
    (bsc1054914, git-fixes).

  - powerpc/powernv: Use kernel crash path for machine
    checks (bsc#1149940 ltc#179958).

  - powerpc/pseries: add missing cpumask.h include file
    (bsc#1065729).

  - powerpc/pseries: correctly track irq state in default
    idle (bsc#1150727 ltc#178925).

  - powerpc/pseries, ps3: panic flush kernel messages before
    halting system (bsc#1149940 ltc#179958).

  - powerpc/rtas: use device model APIs and serialization
    during LPM (bsc#1144123 ltc#178840).

  - powerpc/security: Show powerpc_security_features in
    debugfs (bsc#1131107).

  - powerpc/xive: Fix dump of XIVE interrupt under pseries
    (bsc#1142019).

  - powerpc/xive: Fix loop exit-condition in
    xive_find_target_in_mask() (FATE#322438, bsc#1085030,
    bsc#1145189, LTC#179762).

  - powerpc/xmon: Add a dump of all XIVE interrupts
    (bsc#1142019).

  - powerpc/xmon: Check for HV mode when dumping XIVE info
    from OPAL (bsc#1142019).

  - qede: fix write to free'd pointer error and double free
    of ptp (bsc#1051510).

  - qla2xxx: kABI fixes for v10.01.00.18-k (bcs#1082635
    bcs#1141340 bcs#1143706).

  - raid5-cache: Need to do start() part job after adding
    journal device (git fixes).

  - RDMA/hns: Add mtr support for mixed multihop addressing
    (bsc#1104427 FATE#326416).

  - RDMA/hns: Bugfix for calculating qp buffer size
    (bsc#1104427 FATE#326416).

  - RDMA/hns: Bugfix for filling the sge of srq (bsc#1104427
    FATE#326416).

  - RDMA/hns: Do not stuck in endless timeout loop
    (bsc#1104427 FATE#326416).

  - RDMA/hns: Fix an error code in
    hns_roce_set_user_sq_size() (bsc#1104427 FATE#326416).

  - RDMA/hns: fix inverted logic of readl read and shift
    (bsc#1104427 FATE#326416).

  - RDMA/hns: Fixs hw access invalid dma memory error
    (bsc#1104427 FATE#326416).

  - RDMA/hns: Fixup qp release bug (bsc#1104427
    FATE#326416).

  - RDMA/hns: Modify ba page size for cqe (bsc#1104427
    FATE#326416).

  - RDMA/hns: Remove set but not used variable
    'fclr_write_fail_flag' (bsc#1104427 FATE#326416).

  - RDMA/hns: Remove unnecessary print message in aeq
    (bsc#1104427 FATE#326416).

  - RDMA/hns: Replace magic numbers with #defines
    (bsc#1104427 FATE#326416).

  - RDMA/hns: reset function when removing module
    (bsc#1104427 FATE#326416).

  - RDMA/hns: Set reset flag when hw resetting (bsc#1104427
    FATE#326416).

  - RDMA/hns: Use %pK format pointer print (bsc#1104427
    FATE#326416).

  - refresh: soc: fsl: guts: Add definition for LX2160A
    (fate#326572).

  - regulator: qcom_spmi: Fix math of
    spmi_regulator_set_voltage_time_sel (bsc#1051510).

  - Remove ifdef since SMB3 (and later) now STRONGLY
    preferred (bsc#1051510, bsc#1144333).

  - Remove qla2xxx-specific symbols kABI workarounds. In
    SLE15 1d5e8aad6de2285a00b4e1f2c5ea64a41e74bb7b adds kABI
    whitelists for drivers/scsi/qla2xxx/* because these
    symbols are internal to the driver. This entry was
    dropped from 15 SP1 during a kabi/severities cleanup and
    we grew a few needless kABI hacks to fix these symbols.
    Remove them again since the commit is cherry-picked on
    SP1.

  - Replace lpfc patch with upstream version

  - Revert 'Bluetooth: validate BLE connection interval
    updates' (bsc#1051510).

  - Revert 'cfg80211: fix processing world regdomain when
    non modular' (bsc#1051510).

  - Revert 'dm bufio: fix deadlock with loop device' (git
    fixes).

  - Revert i915 userptr page lock patch (bsc#1145051) This
    patch potentially causes a deadlock between kcompactd,
    as reported on 5.3-rc3. Revert it until a proper fix is
    found.

  - Revert 'net: ena: ethtool: add extra properties
    retrieval via get_priv_flags' (bsc#1139020 bsc#1139021).

  - Revert
    patches.suse/0001-blk-wbt-Avoid-lock-contention-and-thun
    dering-herd-is.patch (bsc#1141543) As we see stalls /
    crashes recently with the relevant code path, revert
    this patch tentatively.

  - Revert 'scsi: ncr5380: Increase register polling limit'
    (git-fixes).

  - Revert 'scsi: prefix header search paths with
    $(srctree)/ (bsc#1136346' This reverts commit
    5f679430713da59f5367aa9499e544e6187ac17c. Reverting this
    commit fixes build for me.

  - Revert 'scsi: ufs: disable vccq if it's not needed by
    UFS device' (git-fixes).

  - rpm/kernel-binary.spec.in: Enable missing modules check.

  - rpmsg: added MODULE_ALIAS for rpmsg_char (bsc#1051510).

  - rpmsg: smd: do not use mananged resources for endpoints
    and channels (bsc#1051510).

  - rpmsg: smd: fix memory leak on channel create
    (bsc#1051510).

  - rsi: improve kernel thread handling to fix kernel panic
    (bsc#1051510).

  - rslib: Fix decoding of shortened codes (bsc#1051510).

  - rslib: Fix handling of of caller provided syndrome
    (bsc#1051510).

  - rtc: pcf8523: do not return invalid date when battery is
    low (bsc#1051510).

  - rtc: pcf8563: Clear event flags and disable interrupts
    before requesting irq (bsc#1051510).

  - rtc: pcf8563: Fix interrupt trigger method
    (bsc#1051510).

  - rxrpc: Fix send on a connected, but unbound socket
    (networking-stable-19_07_25).

  - s390/cio: fix ccw_device_start_timeout API (bsc#1142109
    LTC#179339).

  - s390/dasd: fix endless loop after read unit address
    configuration (bsc#1144912 LTC#179907).

  - s390/qeth: avoid control IO completion stalls
    (bsc#1142109 LTC#179339).

  - s390/qeth: cancel cmd on early error (bsc#1142109
    LTC#179339).

  - s390/qeth: fix request-side race during cmd IO timeout
    (bsc#1142109 LTC#179339).

  - s390/qeth: release cmd buffer in error paths
    (bsc#1142109 LTC#179339).

  - s390/qeth: simplify reply object handling (bsc#1142109
    LTC#179339).

  - samples, bpf: fix to change the buffer size for read()
    (bsc#1051510).

  - samples: mei: use /dev/mei0 instead of /dev/mei
    (bsc#1051510).

  - sched/fair: Do not free p->numa_faults with concurrent
    readers (bsc#1144920).

  - sched/fair: Use RCU accessors consistently for
    ->numa_group (bsc#1144920).

  - scripts/checkstack.pl: Fix arm64 wrong or unknown
    architecture (bsc#1051510).

  - scripts/decode_stacktrace: only strip base path when a
    prefix of the path (bsc#1051510).

  - scripts/decode_stacktrace.sh: prefix addr2line with
    $CROSS_COMPILE (bsc#1051510).

  - scripts/gdb: fix lx-version string output (bsc#1051510).

  - scripts/git_sort/git_sort.py :

  - scsi: aacraid: Fix missing break in switch statement
    (git-fixes).

  - scsi: aacraid: Fix performance issue on logical drives
    (git-fixes).

  - scsi: aic94xx: fix an error code in aic94xx_init()
    (git-fixes).

  - scsi: aic94xx: fix module loading (git-fixes).

  - scsi: bfa: Avoid implicit enum conversion in
    bfad_im_post_vendor_event (bsc#1136496 jsc#SLE-4698).

  - scsi: bfa: bfa_fcs_lport: Mark expected switch
    fall-throughs (bsc#1136496 jsc#SLE-4698).

  - scsi: bfa: bfa_fcs_rport: Mark expected switch
    fall-throughs (bsc#1136496 jsc#SLE-4698).

  - scsi: bfa: bfa_ioc: Mark expected switch fall-throughs
    (bsc#1136496 jsc#SLE-4698).

  - scsi: bfa: clean up a couple of indentation issues
    (bsc#1136496 jsc#SLE-4698).

  - scsi: bfa: convert to strlcpy/strlcat (git-fixes).

  - scsi: bfa: fix calls to dma_set_mask_and_coherent()
    (bsc#1136496 jsc#SLE-4698).

  - scsi: bfa: no need to check return value of
    debugfs_create functions (bsc#1136496 jsc#SLE-4698).

  - scsi: bfa: remove ScsiResult macro (bsc#1136496
    jsc#SLE-4698).

  - scsi: bfa: Remove unused functions (bsc#1136496
    jsc#SLE-4698).

  - scsi: bfa: use dma_set_mask_and_coherent (bsc#1136496
    jsc#SLE-4698).

  - scsi: bnx2fc: Do not allow both a cleanup completion and
    abort completion for the same request (bsc#1144582).

  - scsi: bnx2fc: fix bnx2fc_cmd refcount imbalance in
    send_rec (bsc#1144582).

  - scsi: bnx2fc: fix bnx2fc_cmd refcount imbalance in
    send_srr (bsc#1144582).

  - scsi: bnx2fc: fix incorrect cast to u64 on shift
    operation (git-fixes).

  - scsi: bnx2fc: Fix NULL dereference in error handling
    (git-fixes).

  - scsi: bnx2fc: Limit the IO size according to the FW
    capability (bsc#1144582).

  - scsi: bnx2fc: Only put reference to io_req in
    bnx2fc_abts_cleanup if cleanup times out (bsc#1144582).

  - scsi: bnx2fc: Redo setting source FCoE MAC
    (bsc#1144582).

  - scsi: bnx2fc: Separate out completion flags and
    variables for abort and cleanup (bsc#1144582).

  - scsi: bnx2fc: Update the driver version to 2.12.10
    (bsc#1144582).

  - scsi: core: Fix race on creating sense cache
    (git-fixes).

  - scsi: core: set result when the command cannot be
    dispatched (git-fixes).

  - scsi: core: Synchronize request queue PM status only on
    successful resume (git-fixes).

  - scsi: cxgb4i: fix incorrect spelling 'reveive' ->
    'receive' (bsc#1136346 jsc#SLE-4682).

  - scsi: cxgb4i: get pf number from lldi->pf (bsc#1136346
    jsc#SLE-4682).

  - scsi: cxgb4i: validate tcp sequence number only if chip
    version <= T5 (bsc#1136346 jsc#SLE-4682).

  - scsi: cxlflash: Mark expected switch fall-throughs
    (bsc#1148868).

  - scsi: cxlflash: Prevent deadlock when adapter probe
    fails (git-fixes).

  - scsi: esp_scsi: Track residual for PIO transfers
    (git-fixes) Also, mitigate kABI changes.

  - scsi: fas216: fix sense buffer initialization
    (git-fixes).

  - scsi: hisi_sas: Add support for DIX feature for v3 hw
    (bsc#1137322 bsc#1137323 bsc#1138099 bsc#1138100).

  - scsi: hisi_sas: change queue depth from 512 to 4096
    (bsc#1137322 bsc#1137323 bsc#1138099 bsc#1138100).

  - scsi: hisi_sas: Change SERDES_CFG init value to increase
    reliability of HiLink (bsc#1137322 bsc#1137323
    bsc#1138099 bsc#1138100).

  - scsi: hisi_sas: Disable stash for v3 hw (bsc#1137322
    bsc#1137323 bsc#1138099 bsc#1138100).

  - scsi: hisi_sas: Fix losing directly attached disk when
    hot-plug (bsc#1137322 bsc#1137323 bsc#1138099
    bsc#1138100).

  - scsi: hisi_sas: Ignore the error code between phy down
    to phy up (bsc#1137322 bsc#1137323 bsc#1138099
    bsc#1138100).

  - scsi: hisi_sas: Issue internal abort on all relevant
    queues (bsc#1137322 bsc#1137323 bsc#1138099
    bsc#1138100).

  - scsi: hisi_sas: kabi fixes (bsc#1137322 bsc#1137323
    bsc#1138099 bsc#1138100).

  - scsi: hisi_sas: print PHY RX errors count for later
    revision of v3 hw (bsc#1137322 bsc#1137323 bsc#1138099
    bsc#1138100).

  - scsi: hisi_sas: Reduce HISI_SAS_SGE_PAGE_CNT in size
    (bsc#1137322 bsc#1137323 bsc#1138099 bsc#1138100).

  - scsi: hisi_sas: Reject setting programmed minimum
    linkrate > 1.5G (bsc#1137322 bsc#1137323 bsc#1138099
    bsc#1138100).

  - scsi: hisi_sas: send primitive NOTIFY to SSP situation
    only (bsc#1137322 bsc#1137323 bsc#1138099 bsc#1138100).

  - scsi: hisi_sas: shutdown axi bus to avoid exception CQ
    returned (bsc#1137322 bsc#1137323 bsc#1138099
    bsc#1138100).

  - scsi: hisi_sas: Use pci_irq_get_affinity() for v3 hw as
    experimental (bsc#1137322 bsc#1137323 bsc#1138099
    bsc#1138100).

  - scsi: isci: initialize shost fully before calling
    scsi_add_host() (git-fixes).

  - scsi: libfc: fix NULL pointer dereference on a null
    lport (git-fixes).

  - scsi: libsas: delete sas port if expander discover
    failed (git-fixes).

  - scsi: libsas: Fix rphy phy_identifier for PHYs with end
    devices attached (git-fixes).

  - scsi: libsas: kABI protect struct sas_task_slow
    (bsc#1137322 bsc#1137323 bsc#1138099 bsc#1138100).

  - scsi: libsas: only clear phy->in_shutdown after shutdown
    event done (bsc#1137322 bsc#1137323 bsc#1138099
    bsc#1138100).

  - scsi: lpfc: add check for loss of ndlp when sending RRQ
    (bsc#1148308).

  - scsi: lpfc: Add first and second level hardware
    revisions to sysfs (bsc#1146215).

  - scsi: lpfc: Add MDS driver loopback diagnostics support
    (bsc#1146215).

  - scsi: lpfc: Add NVMe sequence level error recovery
    support (bsc#1146215).

  - scsi: lpfc: Add simple unlikely optimizations to reduce
    NVME latency (bsc#1146215).

  - scsi: lpfc: Avoid unused function warnings
    (bsc#1148308).

  - scsi: lpfc: change snprintf to scnprintf for possible
    overflow (bsc#1146215).

  - scsi: lpfc: Convert timers to use timer_setup()
    (bsc#1148308).

  - scsi: lpfc: correct rcu unlock issue in
    lpfc_nvme_info_show (bsc#1148308).

  - scsi: lpfc: Default fdmi_on to on (bsc#1148308).

  - scsi: lpfc: Fix ADISC reception terminating login state
    if a NVME (bsc#1146215).

  - scsi: lpfc: Fix BlockGuard enablement on FCoE adapters
    (bsc#1146215).

  - scsi: lpfc: Fix coverity warnings (bsc#1146215).

  - scsi: lpfc: Fix crash due to port reset racing vs
    adapter error (bsc#1146215).

  - scsi: lpfc: Fix crash on driver unload in wq free
    (bsc#1146215).

  - scsi: lpfc: Fix crash when cpu count is 1 and null irq
    affinity mask (bsc#1146215).

  - scsi: lpfc: Fix deadlock on host_lock during cable pulls
    (bsc#1146215).

  - scsi: lpfc: Fix devices that do not return after devloss
    followed by (bsc#1146215).

  - scsi: lpfc: Fix discovery when target has no GID_FT
    information (bsc#1146215).

  - scsi: lpfc: Fix ELS field alignments (bsc#1146215).

  - scsi: lpfc: Fix error in remote port address change
    (bsc#1146215).

  - scsi: lpfc: Fix failure to clear non-zero eq_delay after
    io rate (bsc#1146215).

  - scsi: lpfc: Fix FLOGI handling across multiple link
    up/down (bsc#1146215).

  - scsi: lpfc: Fix hang when downloading fw on port enabled
    for nvme (bsc#1146215).

  - scsi: lpfc: Fix irq raising in lpfc_sli_hba_down
    (bsc#1146215).

  - scsi: lpfc: Fix issuing init_vpi mbox on SLI-3 card
    (bsc#1146215).

  - scsi: lpfc: Fix leak of ELS completions on adapter reset
    (bsc#1146215).

  - scsi: lpfc: Fix loss of remote port after devloss due to
    lack of RPIs (bsc#1146215).

  - scsi: lpfc: Fix Max Frame Size value shown in fdmishow
    output (bsc#1146215).

  - scsi: lpfc: Fix null ptr oops updating lpfc_devloss_tmo
    via sysfs (bsc#1146215).

  - scsi: lpfc: Fix nvme first burst module parameter
    description (bsc#1146215).

  - scsi: lpfc: Fix nvme sg_seg_cnt display if HBA does not
    support NVME (bsc#1146215).

  - scsi: lpfc: Fix nvme target mode ABTSing a received ABTS
    (bsc#1146215).

  - scsi: lpfc: Fix Oops in nvme_register with target
    logout/login (bsc#1146215).

  - scsi: lpfc: Fix oops when fewer hdwqs than cpus
    (bsc#1146215).

  - scsi: lpfc: Fix PLOGI failure with high remoteport count
    (bsc#1146215).

  - scsi: lpfc: Fix port relogin failure due to GID_FT
    interaction (bsc#1146215).

  - scsi: lpfc: Fix propagation of devloss_tmo setting to
    nvme transport (bsc#1146215).

  - scsi: lpfc: Fix reported physical link speed on a
    disabled trunked (bsc#1146215).

  - scsi: lpfc: Fix reset recovery paths that are not
    recovering (bsc#1144375).

  - scsi: lpfc: Fix sg_seg_cnt for HBAs that do not support
    NVME (bsc#1146215).

  - scsi: lpfc: Fix sli4 adapter initialization with MSI
    (bsc#1146215).

  - scsi: lpfc: Fix too many sg segments spamming in kernel
    log (bsc#1146215).

  - scsi: lpfc: Fix upcall to bsg done in non-success cases
    (bsc#1146215).

  - scsi: lpfc: Limit xri count for kdump environment
    (bsc#1146215).

  - scsi: lpfc: lpfc_sli: Mark expected switch fall-throughs
    (bsc#1148308).

  - scsi: lpfc: Make some symbols static (bsc#1148308).

  - scsi: lpfc: Merge per-protocol WQ/CQ pairs into single
    per-cpu pair (bsc#1146215).

  - scsi: lpfc: Migrate to %px and %pf in kernel print calls
    (bsc#1146215).

  - scsi: lpfc: no need to check return value of
    debugfs_create functions (bsc#1148308).

  - scsi: lpfc: nvme: avoid hang / use-after-free when
    destroying localport (bsc#1148308).

  - scsi: lpfc: nvmet: avoid hang / use-after-free when
    destroying targetport (bsc#1148308).

  - scsi: lpfc: remove a bogus
    pci_dma_sync_single_for_device call (bsc#1148308).

  - scsi: lpfc: Remove bg debugfs buffers (bsc#1144375).

  - scsi: lpfc: remove NULL check before some freeing
    functions (bsc#1146215).

  - scsi: lpfc: remove null check on nvmebuf (bsc#1148308).

  - scsi: lpfc: remove ScsiResult macro (bsc#1148308).

  - scsi: lpfc: Remove set but not used variable 'psli'
    (bsc#1148308).

  - scsi: lpfc: Remove set but not used variables 'fc_hdr'
    and 'hw_page_size' (bsc#1148308).

  - scsi: lpfc: Remove set but not used variables 'qp'
    (bsc#1148308).

  - scsi: lpfc: Remove set but not used variables 'tgtp'
    (bsc#1148308).

  - scsi: lpfc: Resolve checker warning for
    lpfc_new_io_buf() (bsc#1144375).

  - scsi: lpfc: resolve lockdep warnings (bsc#1148308).

  - scsi: lpfc: Support dynamic unbounded SGL lists on G7
    hardware (bsc#1146215).

  - scsi: lpfc: Update lpfc version to 12.4.0.0
    (bsc#1146215).

  - scsi: lpfc: Use dma_zalloc_coherent (bsc#1148308).

  - scsi: lpfc: use sg helper to iterate over scatterlist
    (bsc#1148308).

  - scsi: mac_scsi: Fix pseudo DMA implementation, take 2
    (git-fixes).

  - scsi: mac_scsi: Increase PIO/PDMA transfer length
    threshold (git-fixes).

  - scsi: megaraid: fix out-of-bound array accesses
    (git-fixes).

  - scsi: megaraid_sas: Fix calculation of target ID
    (git-fixes).

  - scsi: megaraid_sas: IRQ poll to avoid CPU hard lockups
    (bsc#1143962).

  - scsi: megaraid_sas: Release Mutex lock before OCR in
    case of DCMD timeout (bsc#1143962).

  - scsi: NCR5380: Always re-enable reselection interrupt
    (git-fixes).

  - scsi: pmcraid: do not allocate a dma coherent buffer for
    sense data (bsc#1135990 jsc#SLE-4709).

  - scsi: pmcraid: simplify pmcraid_cancel_all a bit
    (bsc#1135990 jsc#SLE-4709).

  - scsi: pmcraid: use generic DMA API (bsc#1135990
    jsc#SLE-4709).

  - scsi: pmcraid: use sg helper to iterate over scatterlist
    (bsc#1135990 jsc#SLE-4709).

  - scsi: prefix header search paths with $(srctree)/
    (bsc#1136346 jsc#SLE-4682).

  - scsi: qedf: Add debug information for unsolicited
    processing (bsc#1149976).

  - scsi: qedf: Add shutdown callback handler (bsc#1149976).

  - scsi: qedf: Add support for 20 Gbps speed (bsc#1149976).

  - scsi: qedf: Check both the FCF and fabric ID before
    servicing clear virtual link (bsc#1149976).

  - scsi: qedf: Check for link state before processing LL2
    packets and send fipvlan retries (bsc#1149976).

  - scsi: qedf: Check for module unloading bit before
    processing link update AEN (bsc#1149976).

  - scsi: qedf: Decrease the LL2 MTU size to 2500
    (bsc#1149976).

  - scsi: qedf: Fix race betwen fipvlan request and response
    path (bsc#1149976).

  - scsi: qedf: Initiator fails to re-login to switch after
    link down (bsc#1149976).

  - scsi: qedf: Print message during bailout conditions
    (bsc#1149976).

  - scsi: qedf: remove memset/memcpy to nfunc and use func
    instead (git-fixes).

  - scsi: qedf: remove set but not used variables
    (bsc#1149976).

  - scsi: qedf: Stop sending fipvlan request on unload
    (bsc#1149976).

  - scsi: qedf: Update module description string
    (bsc#1149976).

  - scsi: qedf: Update the driver version to 8.37.25.20
    (bsc#1149976).

  - scsi: qedf: Update the version to 8.42.3.0
    (bsc#1149976).

  - scsi: qedf: Use discovery list to traverse rports
    (bsc#1149976).

  - scsi: qedi: remove declaration of nvm_image from stack
    (git-fixes).

  - scsi: qla2xxx: Add cleanup for PCI EEH recovery
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Add cleanup for PCI EEH recovery
    (bsc#1129424).

  - scsi: qla2xxx: Allow NVMe IO to resume with short cable
    pull (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Always check the
    qla2x00_wait_for_hba_online() return value
    (bsc#1143706).

  - scsi: qla2xxx: Avoid that Coverity complains about
    dereferencing a NULL rport pointer (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Avoid that lockdep complains about unsafe
    locking in tcm_qla2xxx_close_session() (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Avoid that qla2x00_mem_free() crashes if
    called twice (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Avoid that qlt_send_resp_ctio() corrupts
    memory (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Avoid that qlt_send_resp_ctio() corrupts
    memory (git-fixes).

  - scsi: qla2xxx: Change abort wait_loop from msleep to
    wait_event_timeout (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Change a stack variable into a static
    const variable (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Change data_dsd into an array
    (bsc#1143706).

  - scsi: qla2xxx: Change the return type of
    qla24xx_read_flash_data() (bsc#1143706).

  - scsi: qla2xxx: Change the return type of
    qla2x00_update_ms_fdmi_iocb() into void (bsc#1143706).

  - scsi: qla2xxx: Check secondary image if reading the
    primary image fails (bsc#1143706).

  - scsi: qla2xxx: Check the PCI info string output buffer
    size (bsc#1143706).

  - scsi: qla2xxx: Check the size of firmware data
    structures at compile time (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Cleanup fcport memory to prevent leak
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Cleanup redundant qla2x00_abort_all_cmds
    during unload (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: cleanup trace buffer initialization
    (bsc#1134476).

  - scsi: qla2xxx: Complain if a command is released that is
    owned by the firmware (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Complain if a mailbox command times out
    (bsc#1143706).

  - scsi: qla2xxx: Complain if a soft reset fails
    (bsc#1143706).

  - scsi: qla2xxx: Complain if parsing the version string
    fails (bsc#1143706).

  - scsi: qla2xxx: Complain if sp->done() is not called from
    the completion path (bsc#1143706).

  - scsi: qla2xxx: Complain if waiting for pending commands
    times out (bsc#1143706).

  - scsi: qla2xxx: Complain loudly about reference count
    underflow (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Correct error handling during
    initialization failures (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Declare fourth qla2x00_set_model_info()
    argument const (bsc#1143706).

  - scsi: qla2xxx: Declare local symbols static (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Declare qla24xx_build_scsi_crc_2_iocbs()
    static (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Declare qla2x00_find_new_loop_id() static
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Declare qla_tgt_cmd.cdb const
    (bsc#1143706).

  - scsi: qla2xxx: Declare the fourth ql_dump_buffer()
    argument const (bsc#1143706).

  - scsi: qla2xxx: Disable T10-DIF feature with FC-NVMe
    during probe (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Do not corrupt vha->plogi_ack_list
    (bsc#1143706).

  - scsi: qla2xxx: Enable type checking for the SRB free and
    done callback functions (bsc#1143706).

  - scsi: qla2xxx: Fix abort timeout race condition
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix a format specifier (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix a format specifier (git-fixes).

  - scsi: qla2xxx: Fix an endian bug in
    fcpcmd_is_corrupted() (git-fixes).

  - scsi: qla2xxx: Fix a NULL pointer dereference
    (bsc#1143706).

  - scsi: qla2xxx: Fix a qla24xx_enable_msix() error path
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix a race condition between aborting and
    completing a SCSI command (bsc#1143706).

  - scsi: qla2xxx: Fix a small typo in qla_bsg.c
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix comment alignment in qla_bsg.c
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix device staying in blocked state
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix device staying in blocked state
    (git-fixes).

  - scsi: qla2xxx: Fix different size DMA Alloc/Unmap
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix DMA unmap leak (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix driver reload for ISP82xx
    (bsc#1143706).

  - scsi: qla2xxx: Fix driver unload when FC-NVMe LUNs are
    connected (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix error handling in
    qlt_alloc_qfull_cmd() (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Fix error handling in
    qlt_alloc_qfull_cmd() (git-fixes).

  - scsi: qla2xxx: Fix flash read for Qlogic ISPs
    (bsc#1143706).

  - scsi: qla2xxx: Fix formatting of pointer types
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix fw dump corruption (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix hang in fcport delete path
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix hardirq-unsafe locking (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix hardlockup in abort command during
    driver remove (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix kernel crash after disconnecting NVMe
    devices (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix message indicating vectors used by
    driver (bsc#1143706).

  - scsi: qla2xxx: Fix NULL pointer crash due to stale CPUID
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix NVME cmd and LS cmd timeout race
    condition (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix NVMe port discovery after a short
    device port loss (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix possible fcport NULL pointer
    dereferences (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix premature timer expiration
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix qla24xx_process_bidir_cmd()
    (bsc#1143706).

  - scsi: qla2xxx: Fix race conditions in the code for
    aborting SCSI commands (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Fix Relogin to prevent modifying
    scan_state flag (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix session lookup in qlt_abort_work()
    (bsc#1143706).

  - scsi: qla2xxx: fix spelling mistake 'alredy' ->
    'already' (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Fix stale session (bsc#1143706).

  - scsi: qla2xxx: Fix stuck login session (bsc#1143706).

  - scsi: qla2xxx: Fix use-after-free issues in
    qla2xxx_qpair_sp_free_dma() (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Further limit FLASH region write access
    from SysFS (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Improve Linux kernel coding style
    conformance (bsc#1143706).

  - scsi: qla2xxx: Include the <asm/unaligned.h> header file
    from qla_dsd.h (bsc#1143706).

  - scsi: qla2xxx: Increase the max_sgl_segments to 1024
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Increase the size of the mailbox arrays
    from 4 to 8 (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Inline the qla2x00_fcport_event_handler()
    function (bsc#1143706).

  - scsi: qla2xxx: Insert spaces where required (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Introduce qla2x00_els_dcmd2_free()
    (bsc#1143706).

  - scsi: qla2xxx: Introduce qla2xxx_get_next_handle()
    (bsc#1143706).

  - scsi: qla2xxx: Introduce the be_id_t and le_id_t data
    types for FC src/dst IDs (bsc#1143706).

  - scsi: qla2xxx: Introduce the dsd32 and dsd64 data
    structures (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Introduce the function qla2xxx_init_sp()
    (bsc#1143706).

  - scsi: qla2xxx: Leave a blank line after declarations
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Let the compiler check the type of the
    SCSI command context pointer (bsc#1143706).

  - scsi: qla2xxx: Log the status code if a firmware command
    fails (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Make it explicit that ELS pass-through
    IOCBs use little endian (bsc#1143706).

  - scsi: qla2xxx: Make qla24xx_async_abort_cmd() static
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Make qla2x00_abort_srb() again decrease
    the sp reference count (bsc#1143706).

  - scsi: qla2xxx: Make qla2x00_mem_free() easier to verify
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Make qla2x00_process_response_queue()
    easier to read (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Make qlt_handle_abts_completion() more
    robust (bsc#1143706).

  - scsi: qla2xxx: Make sure that aborted commands are freed
    (bsc#1143706).

  - scsi: qla2xxx: Modify NVMe include directives
    (bsc#1143706).

  - scsi: qla2xxx: move IO flush to the front of NVME rport
    unregistration (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Move qla2x00_clear_loop_id() from
    qla_inline.h into qla_init.c (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Move qla2x00_is_reserved_id() from
    qla_inline.h into qla_init.c (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Move qla2x00_set_fcport_state() from a .h
    into a .c file (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Move qla2x00_set_reserved_loop_ids()
    definition (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Move the <linux/io-64-nonatomic-lo-hi.h>
    include directive (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Move the port_state_str definition from a
    .h to a .c file (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: on session delete, return nvme cmd
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Pass little-endian values to the firmware
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: qla2x00_alloc_fw_dump: set ha->eft
    (bsc#1134476).

  - scsi: qla2xxx: Really fix qla2xxx_eh_abort()
    (bsc#1143706).

  - scsi: qla2xxx: Reduce the number of casts in GID list
    code (bsc#1143706).

  - scsi: qla2xxx: Reduce the number of forward declarations
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Reduce the scope of three local variables
    in qla2xxx_queuecommand() (bsc#1143706).

  - scsi: qla2xxx: Reject
    EH_(abort|device_reset|target_request) (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Remove a comment that refers to the SCSI
    host lock (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Remove an include directive from qla_mr.c
    (bsc#1143706).

  - scsi: qla2xxx: Remove a set-but-not-used variable
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Remove a superfluous forward declaration
    (bsc#1143706).

  - scsi: qla2xxx: Remove a superfluous pointer check
    (bsc#1143706).

  - scsi: qla2xxx: Remove dead code (bsc#1143706).

  - scsi: qla2xxx: remove double assignment in
    qla2x00_update_fcport (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Remove qla_tgt_cmd.data_work and
    qla_tgt_cmd.data_work_free (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Remove qla_tgt_cmd.released (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Remove superfluous sts_entry_* casts
    (bsc#1143706).

  - scsi: qla2xxx: Remove the fcport test from
    qla_nvme_abort_work() (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Remove two superfluous casts (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Remove two superfluous if-tests
    (bsc#1143706).

  - scsi: qla2xxx: Remove two superfluous tests
    (bsc#1143706).

  - scsi: qla2xxx: Remove unnecessary locking from the
    target code (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Remove unnecessary null check
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Remove unreachable code from
    qla83xx_idc_lock() (bsc#1143706).

  - scsi: qla2xxx: Remove useless set memory to zero use
    memset() (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Replace vmalloc + memset with vzalloc
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Report invalid mailbox status codes
    (bsc#1143706).

  - scsi: qla2xxx: Report the firmware status code if a
    mailbox command fails (bsc#1143706).

  - scsi: qla2xxx: Reset the FCF_ASYNC_(SENT|ACTIVE) flags
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Retry fabric Scan on IOCB queue full
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Rework key encoding in
    qlt_find_host_by_d_id() (bsc#1143706).

  - scsi: qla2xxx: Set the qpair in SRB to NULL when SRB is
    released (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Set the responder mode if appropriate for
    ELS pass-through IOCBs (bsc#1143706).

  - scsi: qla2xxx: Set the SCSI command result before
    calling the command done (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Silence Successful ELS IOCB message
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Simplify a debug statement (bsc#1143706).

  - scsi: qla2xxx: Simplify qla24xx_abort_sp_done()
    (bsc#1143706).

  - scsi: qla2xxx: Simplify qla24xx_async_abort_cmd()
    (bsc#1143706).

  - scsi: qla2xxx: Simplify qlt_lport_dump() (bsc#1143706).

  - scsi: qla2xxx: Simplify qlt_send_term_imm_notif()
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Skip FW dump on LOOP initialization error
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Suppress a Coveritiy complaint about
    integer overflow (bsc#1143706).

  - scsi: qla2xxx: Suppress multiple Coverity complaint
    about out-of-bounds accesses (bsc#1143706).

  - scsi: qla2xxx: target: Fix offline port handling and
    host reset handling (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Uninline qla2x00_init_timer()
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Unregister chrdev if module
    initialization fails (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Unregister chrdev if module
    initialization fails (git-fixes).

  - scsi: qla2xxx: Unregister resources in the opposite
    order of the registration order (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Update driver version to 10.01.00.16-k
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Update driver version to 10.01.00.18-k
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Update driver version to 10.01.00.19-k
    (bsc#1143706).

  - scsi: qla2xxx: Update two source code comments
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Update two source code comments
    (git-fixes).

  - scsi: qla2xxx: Use an on-stack completion in
    qla24xx_control_vp() (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Use ARRAY_SIZE() in the definition of
    QLA_LAST_SPEED (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Use common update-firmware-options
    routine for ISP27xx+ (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Use Correct index for Q-Pair array
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Use get/put_unaligned where appropriate
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Use __le64 instead of uint32_t[2] for
    sending DMA addresses to firmware (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Use memcpy() and strlcpy() instead of
    strcpy() and strncpy() (bsc#1143706).

  - scsi: qla2xxx: Use mutex protection during
    qla2x00_sysfs_read_fw_dump() (bsc#1082635 bsc#1141340
    bsc#1143706).

  - scsi: qla2xxx: Use strlcpy() instead of strncpy()
    (bsc#1143706).

  - scsi: qla2xxx: Use tabs instead of spaces for
    indentation (bsc#1143706).

  - scsi: qla2xxx: Use tabs to indent code (bsc#1082635
    bsc#1141340 bsc#1143706).

  - scsi: qla2xxx: Verify locking assumptions at runtime
    (bsc#1143706).

  - scsi: qla4xxx: avoid freeing unallocated dma memory
    (git-fixes).

  - scsi: raid_attrs: fix unused variable warning
    (git-fixes).

  - scsi: sas: Convert timers to use timer_setup()
    (bsc#1137322 bsc#1137323 bsc#1138099 bsc#1138100).

  - scsi: scsi_dh_alua: Fix possible null-ptr-deref
    (git-fixes).

  - scsi: scsi_transport_fc: nvme: display FC-NVMe port
    roles (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: sd: Defer spinning up drive while SANITIZE is in
    progress (git-fixes).

  - scsi: sd: Fix a race between closing an sd device and sd
    I/O (git-fixes).

  - scsi: sd: Fix cache_type_store() (git-fixes).

  - scsi: sd: Optimal I/O size should be a multiple of
    physical block size (git-fixes).

  - scsi: sd: Quiesce warning if device does not report
    optimal I/O size (git-fixes).

  - scsi: sd: use mempool for discard special page
    (git-fixes).

  - scsi: sd_zbc: Fix potential memory leak (git-fixes).

  - scsi: smartpqi: unlock on error in
    pqi_submit_raid_request_synchronous() (git-fixes).

  - scsi: sr: Avoid that opening a CD-ROM hangs with runtime
    power management enabled (git-fixes).

  - scsi: target: iscsi: cxgbit: add missing
    spin_lock_init() (bsc#1136349 jsc#SLE-4685).

  - scsi: tcm_qla2xxx: Minimize #include directives
    (bsc#1082635 bsc#1141340 bsc#1143706).

  - scsi: ufs: Avoid runtime suspend possibly being blocked
    forever (git-fixes).

  - scsi: ufs: Check that space was properly alloced in
    copy_query_response (git-fixes).

  - scsi: ufs: Fix NULL pointer dereference in
    ufshcd_config_vreg_hpm() (git-fixes).

  - scsi: ufs: Fix RX_TERMINATION_FORCE_ENABLE define value
    (git-fixes).

  - scsi: ufs: fix wrong command type of UTRD for UFSHCI
    v2.1 (git-fixes).

  - scsi: use dma_get_cache_alignment() as minimum DMA
    alignment (git-fixes).

  - scsi: virtio_scsi: do not send sc payload with tmfs
    (git-fixes).

  - sdhci-fujitsu: add support for setting the CMD_DAT_DELAY
    attribute (bsc#1145256).

  - signal/cifs: Fix cifs_put_tcp_session to call send_sig
    instead of force_sig (bsc#1144333).

  - sis900: fix TX completion (bsc#1051510).

  - sky2: Disable MSI on ASUS P6T (bsc#1142496).

  - smb2: fix missing files in root share directory listing
    (bsc#1112907, bsc#1144333).

  - smb2: fix typo in definition of a few error flags
    (bsc#1144333).

  - smb2: fix uninitialized variable bug in
    smb2_ioctl_query_info (bsc#1144333).

  - SMB3.1.1: Add GCM crypto to the encrypt and decrypt
    functions (bsc#1144333).

  - SMB3.1.1 dialect is no longer experimental (bsc#1051510,
    bsc#1144333).

  - SMB311: Fix reconnect (bsc#1051510, bsc#1144333).

  - SMB311: Improve checking of negotiate security contexts
    (bsc#1051510, bsc#1144333).

  - smb3.11: replace a 4 with
    server->vals->header_preamble_size (bsc#1144333).

  - smb3: add additional ftrace entry points for entry/exit
    to cifs.ko (bsc#1144333).

  - smb3: add credits we receive from oplock/break PDUs
    (bsc#1144333).

  - smb3: add debug for unexpected mid cancellation
    (bsc#1144333).

  - smb3: Add debug message later in smb2/smb3 reconnect
    path (bsc#1144333).

  - smb3: add define for id for posix create context and
    corresponding struct (bsc#1144333).

  - smb3: Add defines for new negotiate contexts
    (bsc#1144333).

  - smb3: add dynamic trace point for query_info_enter/done
    (bsc#1144333).

  - smb3: add dynamic trace point for smb3_cmd_enter
    (bsc#1144333).

  - smb3: add dynamic tracepoint for timeout waiting for
    credits (bsc#1144333).

  - smb3: add dynamic tracepoints for simple fallocate and
    zero range (bsc#1144333).

  - smb3: Add dynamic trace points for various compounded
    smb3 ops (bsc#1144333).

  - smb3: Add ftrace tracepoints for improved SMB3 debugging
    (bsc#1144333).

  - smb3: Add handling for different FSCTL access flags
    (bsc#1144333).

  - smb3: add missing read completion trace point
    (bsc#1144333).

  - smb3: add module alias for smb3 to cifs.ko
    (bsc#1144333).

  - smb3: add new mount option to retrieve mode from special
    ACE (bsc#1144333).

  - smb3: Add posix create context for smb3.11 posix mounts
    (bsc#1144333).

  - smb3: Add protocol structs for change notify support
    (bsc#1144333).

  - smb3: add reconnect tracepoints (bsc#1144333).

  - smb3: Add SMB3.1.1 GCM to negotiated crypto algorigthms
    (bsc#1144333).

  - smb3: add smb3.1.1 to default dialect list
    (bsc#1144333).

  - smb3: Add support for multidialect negotiate (SMB2.1 and
    later) (bsc#1051510, bsc#1144333).

  - smb3: add support for posix negotiate context
    (bsc#1144333).

  - smb3: add support for statfs for smb3.1.1 posix
    extensions (bsc#1144333).

  - smb3: add tracepoint for sending lease break responses
    to server (bsc#1144333).

  - smb3: add tracepoint for session expired or deleted
    (bsc#1144333).

  - smb3: add tracepoint for slow responses (bsc#1144333).

  - smb3: add trace point for tree connection (bsc#1144333).

  - smb3: add tracepoints for query dir (bsc#1144333).

  - smb3: Add tracepoints for read, write and query_dir
    enter (bsc#1144333).

  - smb3: add tracepoints for smb2/smb3 open (bsc#1144333).

  - smb3: add tracepoint to catch cases where credit refund
    of failed op overlaps reconnect (bsc#1144333).

  - smb3: add way to control slow response threshold for
    logging and stats (bsc#1144333).

  - smb3: allow more detailed protocol info on open files
    for debugging (bsc#1144333).

  - smb3: Allow persistent handle timeout to be configurable
    on mount (bsc#1144333).

  - smb3: allow posix mount option to enable new SMB311
    protocol extensions (bsc#1144333).

  - smb3: allow previous versions to be mounted with
    snapshot= mount parm (bsc#1144333).

  - smb3: Allow query of symlinks stored as reparse points
    (bsc#1144333).

  - smb3: Allow SMB3 FSCTL queries to be sent to server from
    tools (bsc#1144333).

  - smb3: allow stats which track session and share
    reconnects to be reset (bsc#1051510, bsc#1144333).

  - smb3: Backup intent flag missing for directory opens
    with backupuid mounts (bsc#1051510, bsc#1144333).

  - smb3: Backup intent flag missing from compounded ops
    (bsc#1144333).

  - smb3: check for and properly advertise directory lease
    support (bsc#1051510, bsc#1144333).

  - smb3 - clean up debug output displaying network
    interfaces (bsc#1144333).

  - smb3: Cleanup license mess (bsc#1144333).

  - smb3: Clean up query symlink when reparse point
    (bsc#1144333).

  - smb3: create smb3 equivalent alias for cifs
    pseudo-xattrs (bsc#1144333).

  - smb3: directory sync should not return an error
    (bsc#1051510, bsc#1144333).

  - smb3: display bytes_read and bytes_written in smb3 stats
    (bsc#1144333).

  - smb3: display security information in
    /proc/fs/cifs/DebugData more accurately (bsc#1144333).

  - smb3: display session id in debug data (bsc#1144333).

  - smb3: display stats counters for number of slow commands
    (bsc#1144333).

  - smb3: display volume serial number for shares in
    /proc/fs/cifs/DebugData (bsc#1144333).

  - smb3: do not allow insecure cifs mounts when using smb3
    (bsc#1144333).

  - smb3: do not attempt cifs operation in smb3 query info
    error path (bsc#1051510, bsc#1144333).

  - smb3: do not display confusing message on mount to Azure
    servers (bsc#1144333).

  - smb3: do not display empty interface list (bsc#1144333).

  - smb3: Do not ignore O_SYNC/O_DSYNC and O_DIRECT flags
    (bsc#1085536, bsc#1144333).

  - smb3: do not request leases in symlink creation and
    query (bsc#1051510, bsc#1144333).

  - smb3: do not send compression info by default
    (bsc#1144333).

  - smb3: Do not send SMB3 SET_INFO if nothing changed
    (bsc#1051510, bsc#1144333).

  - smb3: enumerating snapshots was leaving part of the data
    off end (bsc#1051510, bsc#1144333).

  - smb3: fill in statfs fsid and correct namelen
    (bsc#1112905, bsc#1144333).

  - smb3: Fix 3.11 encryption to Windows and handle
    encrypted smb3 tcon (bsc#1051510, bsc#1144333).

  - smb3: fix bytes_read statistics (bsc#1144333).

  - smb3: fix corrupt path in subdirs on smb311 with posix
    (bsc#1144333).

  - smb3: Fix deadlock in validate negotiate hits reconnect
    (bsc#1144333).

  - smb3: Fix endian warning (bsc#1144333, bsc#1137884).

  - smb3: Fix enumerating snapshots to Azure (bsc#1144333).

  - smb3: fix large reads on encrypted connections
    (bsc#1144333).

  - smb3: fix lease break problem introduced by compounding
    (bsc#1144333).

  - smb3: Fix length checking of SMB3.11 negotiate request
    (bsc#1051510, bsc#1144333).

  - smb3: fix minor debug output for CONFIG_CIFS_STATS
    (bsc#1144333).

  - smb3: Fix mode on mkdir on smb311 mounts (bsc#1144333).

  - smb3: Fix potential memory leak when processing compound
    chain (bsc#1144333).

  - smb3: fix redundant opens on root (bsc#1144333).

  - smb3: fix reset of bytes read and written stats
    (bsc#1112906, bsc#1144333).

  - smb3: Fix rmdir compounding regression to strict servers
    (bsc#1144333).

  - smb3: Fix root directory when server returns inode
    number of zero (bsc#1051510, bsc#1144333).

  - smb3: Fix SMB3.1.1 guest mounts to Samba (bsc#1051510,
    bsc#1144333).

  - smb3: fix various xid leaks (bsc#1051510, bsc#1144333).

  - smb3: for kerberos mounts display the credential uid
    used (bsc#1144333).

  - smb3: handle new statx fields (bsc#1085536,
    bsc#1144333).

  - smb3: if max_credits is specified then display it in
    /proc/mounts (bsc#1144333).

  - smb3: if server does not support posix do not allow
    posix mount option (bsc#1144333).

  - smb3: improve dynamic tracing of open and posix mkdir
    (bsc#1144333).

  - smb3: increase initial number of credits requested to
    allow write (bsc#1144333).

  - smb3: Kernel oops mounting a encryptData share with
    CONFIG_DEBUG_VIRTUAL (bsc#1144333).

  - smb3: Log at least once if tree connect fails during
    reconnect (bsc#1144333).

  - smb3: make default i/o size for smb3 mounts larger
    (bsc#1144333).

  - smb3: minor cleanup of compound_send_recv (bsc#1144333).

  - smb3: minor debugging clarifications in rfc1001 len
    processing (bsc#1144333).

  - smb3: minor missing defines relating to reparse points
    (bsc#1144333).

  - smb3: missing defines and structs for reparse point
    handling (bsc#1144333).

  - smb3: note that smb3.11 posix extensions mount option is
    experimental (bsc#1144333).

  - smb3: Number of requests sent should be displayed for
    SMB3 not just CIFS (bsc#1144333).

  - smb3: on kerberos mount if server does not specify auth
    type use krb5 (bsc#1051510, bsc#1144333).

  - smb3: on reconnect set PreviousSessionId field
    (bsc#1112899, bsc#1144333).

  - smb3: optimize open to not send query file internal info
    (bsc#1144333).

  - smb3: passthru query info does not check for SMB3 FSCTL
    passthru (bsc#1144333).

  - smb3: print tree id in debugdata in proc to be able to
    help logging (bsc#1144333).

  - smb3: query inode number on open via create context
    (bsc#1144333).

  - smb3: remove noisy warning message on mount
    (bsc#1129664, bsc#1144333).

  - smb3: remove per-session operations from per-tree
    connection stats (bsc#1144333).

  - smb3: rename encryption_required to
    smb3_encryption_required (bsc#1144333).

  - smb3: request more credits on normal (non-large
    read/write) ops (bsc#1144333).

  - smb3: request more credits on tree connect
    (bsc#1144333).

  - smb3: retry on STATUS_INSUFFICIENT_RESOURCES instead of
    failing write (bsc#1144333).

  - smb3: send backup intent on compounded query info
    (bsc#1144333).

  - smb3: send CAP_DFS capability during session setup
    (bsc#1144333).

  - smb3: Send netname context during negotiate protocol
    (bsc#1144333).

  - smb3: show number of current open files in
    /proc/fs/cifs/Stats (bsc#1144333).

  - smb3: simplify code by removing CONFIG_CIFS_SMB311
    (bsc#1051510, bsc#1144333).

  - smb3: smbdirect no longer experimental (bsc#1144333).

  - smb3: snapshot mounts are read-only and make sure info
    is displayable about the mount (bsc#1144333).

  - smb3: track the instance of each session for debugging
    (bsc#1144333).

  - smb3: Track total time spent on roundtrips for each SMB3
    command (bsc#1144333).

  - smb3: trivial cleanup to smb2ops.c (bsc#1144333).

  - smb3: update comment to clarify enumerating snapshots
    (bsc#1144333).

  - smb3: update default requested iosize to 4MB from 1MB
    for recent dialects (bsc#1144333).

  - smb3: Update POSIX negotiate context with POSIX ctxt
    GUID (bsc#1144333).

  - smb3: Validate negotiate request must always be signed
    (bsc#1064597, bsc#1144333).

  - smb3: Warn user if trying to sign connection that
    authenticated as guest (bsc#1085536, bsc#1144333).

  - smbd: Make upper layer decide when to destroy the
    transport (bsc#1144333).

  - SMB: fix leak of validate negotiate info response buffer
    (bsc#1064597, bsc#1144333).

  - SMB: fix validate negotiate info uninitialised memory
    use (bsc#1064597, bsc#1144333).

  - SMB: Validate negotiate (to protect against downgrade)
    even if signing off (bsc#1085536, bsc#1144333).

  - smpboot: Place the __percpu annotation correctly (git
    fixes).

  - soc: rockchip: power-domain: Add a sanity check on
    pd->num_clks (bsc#1144718,bsc#1144813).

  - soc: rockchip: power-domain: use clk_bulk APIs
    (bsc#1144718,bsc#1144813).

  - soc: rockchip: power-domain: Use
    of_clk_get_parent_count() instead of open coding
    (bsc#1144718,bsc#1144813).

  - sound: fix a memory leak bug (bsc#1051510).

  - spi: bcm2835aux: fix corruptions for longer spi
    transfers (bsc#1051510).

  - spi: bcm2835aux: remove dangerous uncontrolled read of
    fifo (bsc#1051510).

  - spi: bcm2835aux: unifying code between polling and
    interrupt driven code (bsc#1051510).

  - st21nfca_connectivity_event_received: null check the
    allocation (bsc#1051510).

  - staging: comedi: dt3000: Fix rounding up of timer
    divisor (bsc#1051510).

  - staging: comedi: dt3000: Fix signed integer overflow
    'divider * base' (bsc#1051510).

  - staging: fsl-dpaa2/ethsw: fix memory leak of
    switchdev_work (bsc#1111666).

  - st_nci_hci_connectivity_event_received: null check the
    allocation (bsc#1051510).

  - supported.conf: Add missing modules (bsc#1066369).

  - supported.conf: Remove duplicate
    drivers/ata/libahci_platform

  - supported.conf: Remove duplicate entries

  - supported.conf: Sort alphabetically, align comments.

  - tcp: Reset bytes_acked and bytes_received when
    disconnecting (networking-stable-19_07_25).

  - test_firmware: fix a memory leak bug (bsc#1051510).

  - tools: bpftool: close prog FD before exit on showing a
    single program (bsc#1109837).

  - tools: bpftool: fix error message (prog -> object)
    (bsc#1109837).

  - tpm: Fix off-by-one when reading
    binary_bios_measurements (bsc#1082555).

  - tpm: Fix TPM 1.2 Shutdown sequence to prevent future TPM
    operations (bsc#1082555).

  - tpm/tpm_i2c_atmel: Return -E2BIG when the transfer is
    incomplete (bsc#1082555).

  - tpm: Unify the send callback behaviour (bsc#1082555).

  - tpm: vtpm_proxy: Suppress error logging when in closed
    state (bsc#1082555).

  - Tree connect for SMB3.1.1 must be signed for
    non-encrypted shares (bsc#1051510, bsc#1144333).

  - treewide: Replace GPLv2 boilerplate/reference with SPDX
    - rule 231 (bsc#1144333).

  - tun: mark small packets as owned by the tap sock
    (bsc#1109837).

  - udf: Fix incorrect final NOT_ALLOCATED (hole) extent
    length (bsc#1148617).

  - Update config files. (bsc#1145687) Add the following
    kernel config to ARM64: CONFIG_ACPI_PCI_SLOT=y
    CONFIG_HOTPLUG_PCI_ACPI=y

  - Update config files. - cifs: add CONFIG_CIFS_DEBUG_KEYS
    to dump encryption keys (bsc#1144333).

  - Update config files. - cifs: allow disabling insecure
    dialects in the config (bsc#1144333).

  - Update config files. - cifs: smbd: Introduce kernel
    config option CONFIG_CIFS_SMB_DIRECT (bsc#1144333).

  - update internal version number for cifs.ko
    (bsc#1144333).

  - Update
    patches.fixes/0001-docs-Fix-conf.py-for-Sphinx-2.0.patch
    (bsc#1135642). Fix patch header.

  - Update
    patches.fixes/MD-fix-invalid-stored-role-for-a-disk-try2
    .patch (bsc#1143765).

  - Update
    patches.fixes/tracing-Fix-bad-use-of-igrab-in-trace_upro
    be.c.patch (bsc#1120046, bsc#1146141).

  - Update
    patches.suse/ceph-remove-request-from-waiting-list-befor
    e-unregister.patch (bsc#1148133 bsc#1138539).

  - Update session and share information displayed for
    debugging SMB2/SMB3 (bsc#1144333).

  - Update version of cifs module (bsc#1144333).

  - usb: cdc-acm: make sure a refcount is taken early enough
    (bsc#1142635).

  - usb: CDC: fix sanity checks in CDC union parser
    (bsc#1142635).

  - usb: cdc-wdm: fix race between write and disconnect due
    to flag abuse (bsc#1051510).

  - usb: chipidea: udc: do not do hardware access if gadget
    has stopped (bsc#1051510).

  - usb: core: Fix races in character device registration
    and deregistraion (bsc#1051510).

  - usb: gadget: composite: Clear 'suspended' on
    reset/disconnect (bsc#1051510).

  - usb: gadget: udc: renesas_usb3: Fix sysfs interface of
    'role' (bsc#1142635).

  - usb: host: fotg2: restart hcd after port reset
    (bsc#1051510).

  - usb: host: ohci: fix a race condition between shutdown
    and irq (bsc#1051510).

  - usb: host: xhci-rcar: Fix timeout in xhci_suspend()
    (bsc#1051510).

  - usb: host: xhci: rcar: Fix typo in compatible string
    matching (bsc#1051510).

  - usb: iowarrior: fix deadlock on disconnect
    (bsc#1051510).

  - usb: serial: option: add D-Link DWM-222 device ID
    (bsc#1051510).

  - usb: serial: option: Add Motorola modem UARTs
    (bsc#1051510).

  - usb: serial: option: Add support for ZTE MF871A
    (bsc#1051510).

  - usb: serial: option: add the BroadMobi BM818 card
    (bsc#1051510).

  - usb-storage: Add new JMS567 revision to unusual_devs
    (bsc#1051510).

  - usb: storage: ums-realtek: Update module parameter
    description for auto_delink_en (bsc#1051510).

  - usb: storage: ums-realtek: Whitelist auto-delink support
    (bsc#1051510).

  - usb: typec: tcpm: free log buf memory when remove debug
    file (bsc#1111666).

  - usb: typec: tcpm: Ignore unsupported/unknown alternate
    mode requests (bsc#1111666).

  - usb: typec: tcpm: remove tcpm dir if no children
    (bsc#1111666).

  - usb: usbfs: fix double-free of usb memory upon submiturb
    error (bsc#1051510).

  - usb: yurex: Fix use-after-free in yurex_delete
    (bsc#1051510).

  - vfs: fix page locking deadlocks when deduping files
    (bsc#1148619).

  - virtio/s390: fix race on airq_areas (bsc#1145357).

  - VMCI: Release resource if the work is already queued
    (bsc#1051510).

  - vrf: make sure skb->data contains ip header to make
    routing (networking-stable-19_07_25).

  - watchdog: bcm2835_wdt: Fix module autoload
    (bsc#1051510).

  - watchdog: core: fix NULL pointer dereference when
    releasing cdev (bsc#1051510).

  - watchdog: f71808e_wdt: fix F81866 bit operation
    (bsc#1051510).

  - watchdog: fix compile time error of pretimeout governors
    (bsc#1051510).

  - wimax/i2400m: fix a memory leak bug (bsc#1051510).

  - x86/asm: Remove dead __GNUC__ conditionals
    (bsc#1112178).

  - x86/boot: Fix memory leak in default_get_smp_config()
    (bsc#1114279).

  - x86/dma: Get rid of iommu_pass_through (bsc#1136039).

  - x86/entry/64/compat: Fix stack switching for XEN PV
    (bsc#1108382).

  - x86/microcode: Fix the microcode load on CPU hotplug for
    real (bsc#1114279).

  - x86/mm: Check for pfn instead of page in
    vmalloc_sync_one() (bsc#1118689).

  - x86/mm: Sync also unmappings in vmalloc_sync_all()
    (bsc#1118689).

  - x86/resctrl: Prevent NULL pointer dereference when local
    MBM is disabled (bsc#1112178).

  - x86/speculation: Allow guests to use SSBD even if host
    does not (bsc#1114279).

  - x86/speculation/mds: Apply more accurate check on
    hypervisor platform (bsc#1114279).

  - x86/unwind: Add hardcoded ORC entry for NULL
    (bsc#1114279).

  - x86/unwind: Handle NULL pointer calls better in frame
    unwinder (bsc#1114279).

  - xdp: unpin xdp umem pages in error path (bsc#1109837).

  - xen/swiotlb: fix condition for calling
    xen_destroy_contiguous_region() (bsc#1065600).

  - xfrm: Fix bucket count reported to userspace
    (bsc#1143300).

  - xfrm: Fix error return code in xfrm_output_one()
    (bsc#1143300).

  - xfrm: Fix NULL pointer dereference in xfrm_input when
    skb_dst_force clears the dst_entry (bsc#1143300).

  - xfrm: Fix NULL pointer dereference when skb_dst_force
    clears the dst_entry (bsc#1143300).

  - xfs: do not crash on null attr fork xfs_bmapi_read
    (bsc#1148035).

  - xfs: do not trip over uninitialized buffer on extent
    read of corrupted inode (bsc#1149053).

  - xfs: dump transaction usage details on log reservation
    overrun (bsc#1145235).

  - xfs: eliminate duplicate icreate tx reservation
    functions (bsc#1145235).

  - xfs: fix missing ILOCK unlock when xfs_setattr_nonsize
    fails due to EDQUOT (bsc#1148032).

  - xfs: fix semicolon.cocci warnings (bsc#1145235).

  - xfs: fix up agi unlinked list reservations
    (bsc#1145235).

  - xfs: include an allocfree res for inobt modifications
    (bsc#1145235).

  - xfs: include inobt buffers in ifree tx log reservation
    (bsc#1145235).

  - xfs: print transaction log reservation on overrun
    (bsc#1145235).

  - xfs: refactor inode chunk alloc/free tx reservation
    (bsc#1145235).

  - xfs: refactor xlog_cil_insert_items() to facilitate
    transaction dump (bsc#1145235).

  - xfs: remove more ondisk directory corruption asserts
    (bsc#1148034).

  - xfs: separate shutdown from ticket reservation print
    helper (bsc#1145235).

  - xfs: truncate transaction does not modify the inobt
    (bsc#1145235)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://acl.bestbits.at"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.kernel.org/show_bug.cgi?id=202935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150933"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
