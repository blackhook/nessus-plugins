#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1390.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105344);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000405", "CVE-2017-1000410", "CVE-2017-11600", "CVE-2017-12193", "CVE-2017-15115", "CVE-2017-16528", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16645", "CVE-2017-16646", "CVE-2017-16939", "CVE-2017-16994", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-7482", "CVE-2017-8824");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-1390) (Dirty COW)");
  script_summary(english:"Check for the openSUSE-2017-1390 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to 4.4.102 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-1000405: A bug in the THP CoW support could be
    used by local attackers to corrupt memory of other
    processes and cause them to crash (bnc#1069496).

  - CVE-2017-1000410: The Linux kernel was affected by an
    information leak in the processing of incoming L2CAP
    commands - ConfigRequest, and ConfigResponse messages.
    (bnc#1070535).

  - CVE-2017-11600: net/xfrm/xfrm_policy.c in the Linux
    kernel did not ensure that the dir value of
    xfrm_userpolicy_id is XFRM_POLICY_MAX or less, which
    allowed local users to cause a denial of service
    (out-of-bounds access) or possibly have unspecified
    other impact via an XFRM_MSG_MIGRATE xfrm Netlink
    message (bnc#1050231).

  - CVE-2017-12193: The
    assoc_array_insert_into_terminal_node function in
    lib/assoc_array.c in the Linux kernel mishandled node
    splitting, which allowed local users to cause a denial
    of service (NULL pointer dereference and panic) via a
    crafted application, as demonstrated by the keyring key
    type, and key addition and link creation operations
    (bnc#1066192).

  - CVE-2017-15115: The sctp_do_peeloff function in
    net/sctp/socket.c in the Linux kernel did not check
    whether the intended netns is used in a peel-off action,
    which allowed local users to cause a denial of service
    (use-after-free and system crash) or possibly have
    unspecified other impact via crafted system calls
    (bnc#1068671).

  - CVE-2017-16528: sound/core/seq_device.c in the Linux
    kernel allowed local users to cause a denial of service
    (snd_rawmidi_dev_seq_free use-after-free and system
    crash) or possibly have unspecified other impact via a
    crafted USB device (bnc#1066629).

  - CVE-2017-16536: The cx231xx_usb_probe function in
    drivers/media/usb/cx231xx/cx231xx-cards.c in the Linux
    kernel allowed local users to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact via a crafted USB device
    (bnc#1066606).

  - CVE-2017-16537: The imon_probe function in
    drivers/media/rc/imon.c in the Linux kernel allowed
    local users to cause a denial of service (NULL pointer
    dereference and system crash) or possibly have
    unspecified other impact via a crafted USB device
    (bnc#1066573).

  - CVE-2017-16645: The ims_pcu_get_cdc_union_desc function
    in drivers/input/misc/ims-pcu.c in the Linux kernel
    allowed local users to cause a denial of service
    (ims_pcu_parse_cdc_data out-of-bounds read and system
    crash) or possibly have unspecified other impact via a
    crafted USB device (bnc#1067132).

  - CVE-2017-16646:
    drivers/media/usb/dvb-usb/dib0700_devices.c in the Linux
    kernel allowed local users to cause a denial of service
    (BUG and system crash) or possibly have unspecified
    other impact via a crafted USB device (bnc#1067105).

  - CVE-2017-16939: The XFRM dump policy implementation in
    net/xfrm/xfrm_user.c in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (use-after-free) via a crafted SO_RCVBUF setsockopt
    system call in conjunction with XFRM_MSG_GETPOLICY
    Netlink messages (bnc#1069702).

  - CVE-2017-16994: The walk_hugetlb_range function in
    mm/pagewalk.c in the Linux kernel mishandled holes in
    hugetlb ranges, which allowed local users to obtain
    sensitive information from uninitialized kernel memory
    via crafted use of the mincore() system call
    (bnc#1069996).

  - CVE-2017-17448: net/netfilter/nfnetlink_cthelper.c in
    the Linux kernel did not require the CAP_NET_ADMIN
    capability for new, get, and del operations, which
    allowed local users to bypass intended access
    restrictions because the nfnl_cthelper_list data
    structure is shared across all net namespaces
    (bnc#1071693).

  - CVE-2017-17449: The __netlink_deliver_tap_skb function
    in net/netlink/af_netlink.c in the Linux kernel did not
    restrict observations of Netlink messages to a single
    net namespace, which allowed local users to obtain
    sensitive information by leveraging the CAP_NET_ADMIN
    capability to sniff an nlmon interface for all Netlink
    activity on the system (bnc#1071694).

  - CVE-2017-17450: net/netfilter/xt_osf.c in the Linux
    kernel did not require the CAP_NET_ADMIN capability for
    add_callback and remove_callback operations, which
    allowed local users to bypass intended access
    restrictions because the xt_osf_fingers data structure
    is shared across all net namespaces (bnc#1071695).

  - CVE-2017-7482: Fixed an overflow when decoding a krb5
    principal. (bnc#1046107).

  - CVE-2017-8824: The dccp_disconnect function in
    net/dccp/proto.c in the Linux kernel allowed local users
    to gain privileges or cause a denial of service
    (use-after-free) via an AF_UNSPEC connect system call
    during the DCCP_LISTEN state (bnc#1070771).

The following non-security bugs were fixed :

  - adm80211: return an error if adm8211_alloc_rings() fails
    (bsc#1031717).

  - adv7604: Initialize drive strength to default when using
    DT (bnc#1012382).

  - af_netlink: ensure that NLMSG_DONE never fails in dumps
    (bnc#1012382).

  - alsa: caiaq: Fix stray URB at probe error path
    (bnc#1012382).

  - alsa: hda: Add Raven PCI ID (bnc#1012382).

  - alsa: hda - Apply ALC269_FIXUP_NO_SHUTUP on
    HDA_FIXUP_ACT_PROBE (bnc#1012382).

  - alsa: hda/ca0132 - Fix memory leak at error path
    (bsc#1031717).

  - alsa: hda - fix headset mic problem for Dell machines
    with alc236 (bnc#1012382).

  - alsa: hda - No loopback on ALC299 codec (git-fixes).

  - alsa: hda/realtek: Add headset mic support for Intel NUC
    Skull Canyon (bsc#1031717).

  - alsa: hda/realtek - Add new codec ID ALC299
    (bnc#1012382).

  - alsa: hda/realtek - Add support for ALC236/ALC3204
    (bnc#1012382).

  - alsa: hda/realtek - Fix ALC700 family no sound issue
    (bsc#1031717).

  - alsa: hda: Remove superfluous '-' added by printk
    conversion (bnc#1012382).

  - alsa: line6: Fix leftover URB at error-path during probe
    (bnc#1012382).

  - alsa: pcm: update tstamp only if audio_tstamp changed
    (bsc#1031717).

  - alsa: seq: Avoid invalid lockdep class warning
    (bsc#1031717).

  - alsa: seq: Enable 'use' locking in all configurations
    (bnc#1012382).

  - alsa: seq: Fix copy_from_user() call inside lock
    (bnc#1012382).

  - alsa: seq: Fix nested rwsem annotation for lockdep splat
    (bnc#1012382).

  - alsa: seq: Fix OSS sysex delivery in OSS emulation
    (bnc#1012382).

  - alsa: timer: Add missing mutex lock for compat ioctls
    (bnc#1012382).

  - alsa: timer: Remove kernel warning at compat ioctl error
    paths (bsc#1031717).

  - alsa: usb-audio: Add native DSD support for Pro-Ject Pre
    Box S2 Digital (bnc#1012382).

  - alsa: usb-audio: Add sanity checks in v2 clock parsers
    (bsc#1031717).

  - alsa: usb-audio: Add sanity checks to FE parser
    (bsc#1031717).

  - alsa: usb-audio: Fix potential out-of-bound access at
    parsing SU (bsc#1031717).

  - alsa: usb-audio: Kill stray URB at exiting
    (bnc#1012382).

  - alsa: usb-audio: uac1: Invalidate ctl on interrupt
    (bsc#1031717).

  - alsa: vx: Do not try to update capture stream before
    running (bnc#1012382).

  - alsa: vx: Fix possible transfer overflow (bnc#1012382).

  - Apply generic ppc build fixes to vanilla (bsc#1070805)

  - arm64: dts: NS2: reserve memory for Nitro firmware
    (bnc#1012382).

  - arm64: ensure __dump_instr() checks addr_limit
    (bnc#1012382).

  - arm64: fix dump_instr when PAN and UAO are in use
    (bnc#1012382).

  - arm: 8715/1: add a private asm/unaligned.h
    (bnc#1012382).

  - arm: 8720/1: ensure dump_instr() checks addr_limit
    (bnc#1012382).

  - arm: 8721/1: mm: dump: check hardware RO bit for LPAE
    (bnc#1012382).

  - arm: 8722/1: mm: make STRICT_KERNEL_RWX effective for
    LPAE (bnc#1012382).

  - arm: crypto: reduce priority of bit-sliced AES cipher
    (bnc#1012382).

  - arm: dts: Fix am335x and dm814x scm syscon to probe
    children (bnc#1012382).

  - arm: dts: Fix compatible for ti81xx uarts for 8250
    (bnc#1012382).

  - arm: dts: Fix omap3 off mode pull defines (bnc#1012382).

  - arm: dts: mvebu: pl310-cache disable double-linefill
    (bnc#1012382).

  - arm: OMAP2+: Fix init for multiple quirks for the same
    SoC (bnc#1012382).

  - arm: omap2plus_defconfig: Fix probe errors on UARTs 5
    and 6 (bnc#1012382).

  - arm: pxa: Do not rely on public mmc header to include
    leds.h (bnc#1012382).

  - asm/sections: add helpers to check for section data
    (bsc#1063026).

  - asoc: adau17x1: Workaround for noise bug in ADC
    (bnc#1012382).

  - asoc: cs42l56: Fix reset GPIO name in example DT binding
    (bsc#1031717).

  - asoc: davinci-mcasp: Fix an error handling path in
    'davinci_mcasp_probe()' (bsc#1031717).

  - asoc: rsnd: do not double free kctrl (bnc#1012382).

  - asoc: samsung: Fix possible double iounmap on s3c24xx
    driver probe failure (bsc#1031717).

  - asoc: wm_adsp: Do not overrun firmware file buffer when
    reading region data (bnc#1012382).

  - ata: ATA_BMDMA should depend on HAS_DMA (bnc#1012382).

  - ata: fixes kernel crash while tracing
    ata_eh_link_autopsy event (bnc#1012382).

  - ata: SATA_HIGHBANK should depend on HAS_DMA
    (bnc#1012382).

  - ata: SATA_MV should depend on HAS_DMA (bnc#1012382).

  - ath10k: convert warning about non-existent OTP board id
    to debug message (git-fixes).

  - ath10k: fix a warning during channel switch with
    multiple vaps (bsc#1031717).

  - ath10k: fix board data fetch error message
    (bsc#1031717).

  - ath10k: fix diag_read to collect data for larger memory
    (bsc#1031717).

  - ath10k: fix incorrect txpower set by P2P_DEVICE
    interface (bnc#1012382).

  - ath10k: fix potential memory leak in
    ath10k_wmi_tlv_op_pull_fw_stats() (bnc#1012382).

  - ath10k: free cached fw bin contents when get board id
    fails (bsc#1031717).

  - ath10k: ignore configuring the incorrect board_id
    (bnc#1012382).

  - ath10k: set CTS protection VDEV param only if VDEV is up
    (bnc#1012382).

  - ath9k_htc: check for underflow in ath9k_htc_rx_msg()
    (bsc#1031717).

  - ath9k: off by one in ath9k_hw_nvram_read_array()
    (bsc#1031717).

  - autofs: do not fail mount for transient error
    (bsc#1065180).

  - backlight: adp5520: Fix error handling in
    adp5520_bl_probe() (bnc#1012382).

  - backlight: lcd: Fix race condition during register
    (bnc#1012382).

  - bcache: check ca->alloc_thread initialized before wake
    up it (bnc#1012382).

  - blacklist 0278b34bf15f spi: spidev_test: Fix buffer
    overflow in unescape() This is a binary built from
    Documentation and the build logs do not show it built

  - blacklist.conf: 79b63f12abcbbd2caf7064b294af648a87de07ff
    # bsc#1061756 may break existing setups

  - blacklist.conf: Add ath10k, mmc and rtl8192u commits
    (bsc#1031717)

  - blacklist.conf: Add drm/i915 blacklist (bsc#1031717)

  - blacklist.conf: added misc commits (bsc#1031717)

  - blacklist.conf: Add misc entries (bsc#1031717)

  - blacklist.conf: Blacklist 33e465ce7cb3 ('percpu_ref:
    allow operation mode switching operations to be called
    concurrently'). The benefits are not worth the possible
    risks eventually introduced.

  - blacklist.conf: blacklisted 16af97dc5a89 (bnc#1053919)

  - blacklist.conf: blacklist not-applicable patch
    (bsc#1071231)

  - blacklist.conf: commit fe22cd9b7c980b8b948 ('printk:
    help pr_debug and pr_devel to optimize out arguments')
    is just a cosmetic change.

  - blacklist.conf: Update blacklist (bsc#1031717)

  - blacklist.conf: Update iwlwifi blacklist (bsc#1031717)

  - blacklist.conf: yet another serial entry (bsc#1031717)

  - block: Fix a race between blk_cleanup_queue() and
    timeout handling (FATE#319965, bsc#964944).

  - bluetooth: btusb: fix QCA Rome suspend/resume
    (bnc#1012382).

  - bnxt_en: Call firmware to approve the random VF MAC
    address (bsc#963575 FATE#320144).

  - bnxt_en: Do not setup MAC address in
    bnxt_hwrm_func_qcaps() (bsc#963575 FATE#320144).

  - bnxt_en: Fix possible corrupted NVRAM parameters from
    firmware response (bsc#963575 FATE#320144).

  - bnxt_en: Fix VF PCIe link speed and width logic
    (bsc#963575 FATE#320144).

  - bnxt_en: Re-arrange bnxt_hwrm_func_qcaps() (bsc#963575
    FATE#320144).

  - bnxt_en: use eth_hw_addr_random() (bsc#963575
    FATE#320144).

  - bonding: discard lowest hash bit for 802.3ad layer3+4
    (bnc#1012382).

  - bpf: one perf event close won't free bpf program
    attached by another perf event (bnc#1012382).

  - bpf/verifier: reject BPF_ALU64|BPF_END (bnc#1012382).

  - brcmfmac: add length check in
    brcmf_cfg80211_escan_handler() (bnc#1012382).

  - brcmfmac: remove setting IBSS mode when stopping AP
    (bnc#1012382).

  - brcmsmac: make some local variables 'static const' to
    reduce stack size (bnc#1012382).

  - bt8xx: fix memory leak (bnc#1012382).

  - btrfs: add a node counter to each of the rbtrees
    (bsc#974590 bsc#1030061 bsc#1022914 bsc#1017461).

  - btrfs: add cond_resched() calls when resolving backrefs
    (bsc#974590 bsc#1030061 bsc#1022914 bsc#1017461).

  - btrfs: allow backref search checks for shared extents
    (bsc#974590 bsc#1030061 bsc#1022914 bsc#1017461).

  - btrfs: backref, add tracepoints for prelim_ref insertion
    and merging (bsc#974590 bsc#1030061 bsc#1022914
    bsc#1017461).

  - btrfs: backref, add unode_aux_to_inode_list helper
    (bsc#974590 bsc#1030061 bsc#1022914 bsc#1017461).

  - btrfs: backref, cleanup __ namespace abuse (bsc#974590
    bsc#1030061 bsc#1022914 bsc#1017461).

  - btrfs: backref, constify some arguments (bsc#974590
    bsc#1030061 bsc#1022914 bsc#1017461).

  - btrfs: btrfs_check_shared should manage its own
    transaction (bsc#974590 bsc#1030061 bsc#1022914
    bsc#1017461).

  - btrfs: clean up extraneous computations in
    add_delayed_refs (bsc#974590 bsc#1030061 bsc#1022914
    bsc#1017461).

  - btrfs: constify tracepoint arguments (bsc#974590
    bsc#1030061 bsc#1022914 bsc#1017461).

  - btrfs: convert prelimary reference tracking to use
    rbtrees (bsc#974590 bsc#1030061 bsc#1022914
    bsc#1017461).

  - btrfs: fix leak and use-after-free in
    resolve_indirect_refs (bsc#974590 bsc#1030061
    bsc#1022914 bsc#1017461).

  - btrfs: Fix typo in may_commit_transaction Rather than
    comparing the result of the percpu comparison I was
    comparing the value of the percpu counter against 0 or
    1.

  - btrfs: remove ref_tree implementation from backref.c
    (bsc#974590 bsc#1030061 bsc#1022914 bsc#1017461).

  - btrfs: return the actual error value from from
    btrfs_uuid_tree_iterate (bnc#1012382).

  - btrfs: struct-funcs, constify readers (bsc#974590
    bsc#1030061 bsc#1022914 bsc#1017461).

  - bus: mbus: fix window size calculation for 4GB windows
    (bnc#1012382).

  - can: c_can: do not indicate triple sampling support for
    D_CAN (bnc#1012382).

  - can: esd_usb2: Fix can_dlc value for received RTR,
    frames (bnc#1012382).

  - can: gs_usb: fix busy loop if no more TX context is
    available (bnc#1012382).

  - can: kvaser_usb: Correct return value in printout
    (bnc#1012382).

  - can: kvaser_usb: Ignore CMD_FLUSH_QUEUE_REPLY messages
    (bnc#1012382).

  - can: sun4i: fix loopback mode (bnc#1012382).

  - can: sun4i: handle overrun in RX FIFO (bnc#1012382).

  - cdc_ncm: Set NTB format again after altsetting switch
    for Huawei devices (bnc#1012382).

  - ceph: clean up unsafe d_parent accesses in
    build_dentry_path (bnc#1012382).

  - ceph: unlock dangling spinlock in try_flush_caps()
    (bsc#1065639).

  - cgroup, net_cls: iterate the fds of only the tasks which
    are being migrated (bnc#1064926).

  - cifs: add build_path_from_dentry_optional_prefix()
    (fate#323482)

  - cifs: Add capability to decrypt big read responses
    (FATE#324404). Allow to decrypt transformed packets that
    are bigger than the big buffer size. In particular it is
    used for read responses that can only exceed the big
    buffer size.

  - cifs: Add capability to transform requests before
    sending (FATE#324404). This will allow us to do protocol
    specific tranformations of packets before sending to the
    server. For SMB3 it can be used to support encryption.

  - cifs: Add copy into pages callback for a read operation
    (FATE#324404). Since we have two different types of
    reads (pagecache and direct) we need to process such
    responses differently after decryption of a packet. The
    change allows to specify a callback that copies a read
    payload data into preallocated pages.

  - cifs: Add mid handle callback (FATE#324404). We need to
    process read responses differently because the data
    should go directly into preallocated pages. This can be
    done by specifying a mid handle callback.

  - cifs: Add soft dependencies (FATE#324404). List soft
    dependencies of cifs so that mkinitrd and dracut can
    include the required helper modules.

  - cifs: Add transform header handling callbacks
    (FATE#324404). We need to recognize and parse
    transformed packets in demultiplex thread to find a
    corresponsing mid and process it further.

  - cifs: add use_ipc flag to SMB2_ioctl() (fate#323482)

  - cifs: Allow to switch on encryption with seal mount
    option (FATE#324404). This allows users to inforce
    encryption for SMB3 shares if a server supports it.

  - cifs: check MaxPathNameComponentLength != 0 before using
    it (bnc#1012382).

  - cifs: Decrypt and process small encrypted packets
    (FATE#324404). Allow to decrypt transformed packets,
    find a corresponding mid and process as usual further.

  - cifs: do not bother with kmap on read_pages side
    (FATE#324404). just do ITER_BVEC recvmsg

  - cifs: Enable encryption during session setup phase
    (FATE#324404). In order to allow encryption on SMB
    connection we need to exchange a session key and
    generate encryption and decryption keys.

  - cifs: Encrypt SMB3 requests before sending
    (FATE#324404). This change allows to encrypt packets if
    it is required by a server for SMB sessions or tree
    connections.

  - cifs: fix circular locking dependency (bsc#1064701).

  - cifs: Fix some return values in case of error in
    'crypt_message' (fate#324404).

  - cifs: Fix sparse warnings (fate#323482)

  - cifs: implement get_dfs_refer for SMB2+ (fate#323482)

  - cifs: let ses->ipc_tid hold smb2 TreeIds (fate#323482)

  - cifs: Make send_cancel take rqst as argument
    (FATE#324404).

  - cifs: Make SendReceive2() takes resp iov (FATE#324404).
    Now SendReceive2 frees the first iov and returns a
    response buffer in it that increases a code complexity.
    Simplify this by making a caller responsible for freeing
    request buffer itself and returning a response buffer in
    a separate iov.

  - cifs: move DFS response parsing out of SMB1 code
    (fate#323482)

  - cifs: no need to wank with copying and advancing iovec
    on recvmsg side either (FATE#324404).

  - cifs: Only select the required crypto modules
    (FATE#324404). The sha256 and cmac crypto modules are
    only needed for SMB2+, so move the select statements to
    config CIFS_SMB2. Also select CRYPTO_AES there as SMB2+
    needs it.

  - cifs: Prepare for encryption support (first part). Add
    decryption and encryption key generation. (FATE#324404).

  - cifs_readv_receive: use cifs_read_from_socket()
    (FATE#324404).

  - cifs: Reconnect expired SMB sessions (bnc#1012382).

  - cifs: remove any preceding delimiter from prefix_path
    (fate#323482)

  - cifs: Send RFC1001 length in a separate iov
    (FATE#324404). In order to simplify further encryption
    support we need to separate RFC1001 length and SMB2
    header when sending a request. Put the length field in
    iov[0] and the rest of the packet into following iovs.

  - cifs: Separate RFC1001 length processing for SMB2 read
    (FATE#324404). Allocate and initialize SMB2 read request
    without RFC1001 length field to directly call
    cifs_send_recv() rather than SendReceive2() in a read
    codepath.

  - cifs: Separate SMB2 header structure (FATE#324404). In
    order to support compounding and encryption we need to
    separate RFC1001 length field and SMB2 header structure
    because the protocol treats them differently. This
    change will allow to simplify parsing of such complex
    SMB2 packets further.

  - cifs: Separate SMB2 sync header processing
    (FATE#324404). Do not process RFC1001 length in
    smb2_hdr_assemble() because it is not a part of SMB2
    header. This allows to cleanup the code and adds a
    possibility combine several SMB2 packets into one for
    compounding.

  - cifs: set signing flag in SMB2+ TreeConnect if needed
    (fate#323482)

  - cifs: Simplify SMB2 and SMB311 dependencies
    (FATE#324404). * CIFS_SMB2 depends on CIFS, which
    depends on INET and selects NLS. So these dependencies
    do not need to be repeated for CIFS_SMB2. * CIFS_SMB311
    depends on CIFS_SMB2, which depends on INET. So this
    dependency does not need to be repeated for CIFS_SMB311.

  - cifs: use DFS pathnames in SMB2+ Create requests
    (fate#323482)

  - clk: ti: dra7-atl-clock: fix child-node lookups
    (bnc#1012382).

  - clk: ti: dra7-atl-clock: Fix of_node reference counting
    (bnc#1012382).

  - clockevents/drivers/cs5535: Improve resilience to
    spurious interrupts (bnc#1012382).

  - cma: fix calculation of aligned offset (VM
    Functionality, bsc#1050060).

  - coda: fix 'kernel memory exposure attempt' in fsync
    (bnc#1012382).

  - cpufreq: CPPC: add ACPI_PROCESSOR dependency
    (bnc#1012382).

  - crypto: shash - Fix zero-length shash ahash digest crash
    (bnc#1012382).

  - crypto: vmx - disable preemption to enable vsx in
    aes_ctr.c (bnc#1012382).

  - crypto: x86/sha1-mb - fix panic due to unaligned access
    (bnc#1012382).

  - crypto: xts - Add ECB dependency (bnc#1012382).

  - cx231xx: Fix I2C on Internal Master 3 Bus (bnc#1012382).

  - cxgb4: Fix error codes in c4iw_create_cq()
    (bsc#1021424).

  - cxl: Fix DAR check & use REGION_ID instead of opencoding
    (bsc#1066223).

  - cxl: Fix leaking pid refs in some error paths
    (bsc#1066223).

  - cxl: Force context lock during EEH flow (bsc#1066223).

  - cxl: Prevent adapter reset if an active context exists
    (bsc#1066223).

  - cxl: Route eeh events to all drivers in
    cxl_pci_error_detected() (bsc#1066223).

  - direct-io: Prevent NULL pointer access in
    submit_page_section (bnc#1012382).

  - Disable IPMI fix patches due to regression (bsc#1071833)

  - Disable
    patches.kernel.org/4.4.93-022-fix-unbalanced-page-refcou
    nting-in-bio_map_use.patch (bsc#1070767) Refresh
    patches.drivers/0004-bio-use-offset_in_page-macro.patch.

  - dmaengine: dmatest: warn user when dma test times out
    (bnc#1012382).

  - dmaengine: edma: Align the memcpy acnt array size with
    the transfer (bnc#1012382).

  - dmaengine: zx: set DMA_CYCLIC cap_mask bit
    (bnc#1012382).

  - dm bufio: fix integer overflow when limiting maximum
    cache size (bnc#1012382).

  - dm: fix race between dm_get_from_kobject() and
    __dm_destroy() (bnc#1012382).

  - drivers: dma-mapping: Do not leave an invalid
    area->pages pointer in dma_common_contiguous_remap()
    (Git-fixes, bsc#1065692).

  - drm/amdgpu: when dpm disabled, also need to stop/start
    vce (bnc#1012382).

  - drm/amdkfd: NULL dereference involving create_process()
    (bsc#1031717).

  - drm: Apply range restriction after color adjustment when
    allocation (bnc#1012382).

  - drm/armada: Fix compile fail (bnc#1012382).

  - drm: drm_minor_register(): Clean up debugfs on failure
    (bnc#1012382).

  - drm: gma500: fix logic error (bsc#1031717).

  - drm/i915/bxt: set min brightness from VBT (bsc#1031717).

  - drm/i915: Do not try indexed reads to alternate slave
    addresses (bsc#1031717).

  - drm/i915: fix backlight invert for non-zero minimum
    brightness (bsc#1031717).

  - drm/i915: Prevent zero length 'index' write
    (bsc#1031717).

  - drm/i915: Read timings from the correct transcoder in
    intel_crtc_mode_get() (bsc#1031717).

  - drm/msm: fix an integer overflow test (bnc#1012382).

  - drm/msm: Fix potential buffer overflow issue
    (bnc#1012382).

  - drm/nouveau/bsp/g92: disable by default (bnc#1012382).

  - drm/nouveau/gr: fallback to legacy paths during firmware
    lookup (bsc#1031717).

  - drm/nouveau/mmu: flush tlbs before deleting page tables
    (bnc#1012382).

  - drm/omap: Fix error handling path in 'omap_dmm_probe()'
    (bsc#1031717).

  - drm/panel: simple: Add missing panel_simple_unprepare()
    calls (bsc#1031717).

  - drm/sti: sti_vtg: Handle return NULL error from
    devm_ioremap_nocache (bnc#1012382).

  - drm/vc4: Fix leak of HDMI EDID (bsc#1031717).

  - drm/vmwgfx: Fix Ubuntu 17.10 Wayland black screen issue
    (bnc#1012382).

  - e1000e: Fix error path in link detection (bnc#1012382).

  - e1000e: Fix return value test (bnc#1012382).

  - e1000e: Separate signaling for link check/link up
    (bnc#1012382).

  - ecryptfs: fix dereference of NULL user_key_payload
    (bnc#1012382).

  - eCryptfs: use after free in ecryptfs_release_messaging()
    (bsc#1012829).

  - epoll: avoid calling ep_call_nested() from
    ep_poll_safewake() (bsc#1056427).

  - epoll: remove ep_call_nested() from ep_eventpoll_poll()
    (bsc#1056427).

  - ext4: cleanup goto next group (bsc#1066285).

  - ext4: do not use stripe_width if it is not set
    (bnc#1012382).

  - ext4: fix interaction between i_size, fallocate, and
    delalloc after a crash (bnc#1012382).

  - ext4: fix stripe-unaligned allocations (bnc#1012382).

  - ext4: in ext4_seek_(hole,data), return -ENXIO for
    negative offsets (bnc#1012382).

  - ext4: reduce lock contention in __ext4_new_inode
    (bsc#1066285).

  - extcon: palmas: Check the parent instance to prevent the
    NULL (bnc#1012382).

  - exynos4-is: fimc-is: Unmap region obtained by of_iomap()
    (bnc#1012382).

  - f2fs crypto: add missing locking for keyring_key access
    (bnc#1012382).

  - f2fs crypto: replace some BUG_ON()'s with error checks
    (bnc#1012382).

  - f2fs: do not wait for writeback in write_begin
    (bnc#1012382).

  - fealnx: Fix building error on MIPS (bnc#1012382).

  - fix a page leak in vhost_scsi_iov_to_sgl() error
    recovery (bnc#1012382).

  - Fix tracing sample code warning (bnc#1012382).

  - fix unbalanced page refcounting in bio_map_user_iov
    (bnc#1012382).

  - fm10k: request reset when mbx->state changes
    (bnc#1012382).

  - fm10k: Use smp_rmb rather than read_barrier_depends
    (bnc#1012382).

  - fs/9p: Compare qid.path in v9fs_test_inode
    (bsc#1012829).

  - fs-cache: fix dereference of NULL user_key_payload
    (bnc#1012382).

  - fscrypt: fix dereference of NULL user_key_payload
    (bnc#1012382).

  - fscrypt: lock mutex before checking for bounce page pool
    (bnc#1012382).

  - fscrypto: require write access to mount to set
    encryption policy (bnc#1012382).

  - fuse: fix READDIRPLUS skipping an entry (bnc#1012382).

  - gpu: drm: mgag200: mgag200_main:- Handle error from
    pci_iomap (bnc#1012382).

  - hid: elo: clear BTN_LEFT mapping (bsc#1065866).

  - hid: usbhid: fix out-of-bounds bug (bnc#1012382).

  - hsi: ssi_protocol: double free in ssip_pn_xmit()
    (bsc#1031717).

  - i2c: at91: ensure state is restored after suspending
    (bnc#1012382).

  - i2c: cadance: fix ctrl/addr reg write order
    (bsc#1031717).

  - i2c: imx: Use correct function to write to register
    (bsc#1031717).

  - i2c: ismt: Separate I2C block read from SMBus block read
    (bnc#1012382).

  - i2c: riic: correctly finish transfers (bnc#1012382).

  - i2c: riic: fix restart condition (git-fixes).

  - i40e: Use smp_rmb rather than read_barrier_depends
    (bnc#1012382).

  - i40evf: Use smp_rmb rather than read_barrier_depends
    (bnc#1012382).

  - ib/core: Fix calculation of maximum RoCE MTU
    (bsc#1022595 FATE#322350).

  - ib/core: Namespace is mandatory input for address
    resolution (bsc#1022595 FATE#322350).

  - ib/ipoib: Change list_del to list_del_init in the tx
    object (bnc#1012382).

  - ib/ipoib: Clean error paths in add port (bsc#1022595
    FATE#322350).

  - ib/ipoib: Prevent setting negative values to
    max_nonsrq_conn_qp (bsc#1022595 FATE#322350).

  - ib/ipoib: Remove double pointer assigning (bsc#1022595
    FATE#322350).

  - ib/ipoib: Set IPOIB_NEIGH_TBL_FLUSH after flushed
    completion initialization (bsc#1022595 FATE#322350).

  - ib/mlx5: Fix RoCE Address Path fields (bsc#966170
    FATE#320225 bsc#966172 FATE#320226).

  - ibmvnic: Add netdev_dbg output for debugging
    (fate#323285).

  - ibmvnic: Add vnic client data to login buffer
    (bsc#1069942).

  - ibmvnic: Convert vnic server reported statistics to cpu
    endian (fate#323285).

  - ibmvnic: Enable scatter-gather support (bsc#1066382).

  - ibmvnic: Enable TSO support (bsc#1066382).

  - ibmvnic: Feature implementation of Vital Product Data
    (VPD) for the ibmvnic driver (bsc#1069942).

  - ibmvnic: Fix calculation of number of TX header
    descriptors (bsc#1066382).

  - ibmvnic: fix dma_mapping_error call (bsc#1069942).

  - ibmvnic: Fix failover error path for non-fatal resets
    (bsc#1066382).

  - ibmvnic: Implement .get_channels (fate#323285).

  - ibmvnic: Implement .get_ringparam (fate#323285).

  - ibmvnic: Implement per-queue statistics reporting
    (fate#323285).

  - ibmvnic: Let users change net device features
    (bsc#1066382).

  - ibmvnic: Update reset infrastructure to support tunable
    parameters (bsc#1066382).

  - ib/srp: Avoid that a cable pull can trigger a kernel
    crash (bsc#1022595 FATE#322350).

  - ib/srpt: Do not accept invalid initiator port names
    (bnc#1012382).

  - ib/uverbs: Fix device cleanup (bsc#1022595 FATE#322350).

  - ib/uverbs: Fix NULL pointer dereference during device
    removal (bsc#1022595 FATE#322350).

  - igb: close/suspend race in netif_device_detach
    (bnc#1012382).

  - igb: Fix hw_dbg logging in igb_update_flash_i210
    (bnc#1012382).

  - igb: reset the PHY before reading the PHY ID
    (bnc#1012382).

  - igb: Use smp_rmb rather than read_barrier_depends
    (bnc#1012382).

  - igbvf: Use smp_rmb rather than read_barrier_depends
    (bnc#1012382).

  - iio: adc: xilinx: Fix error handling (bnc#1012382).

  - iio: dummy: events: Add missing break (bsc#1031717).

  - iio: light: fix improper return value (bnc#1012382).

  - iio: trigger: free trigger resource correctly
    (bnc#1012382).

  - ima: do not update security.ima if appraisal status is
    not INTEGRITY_PASS (bnc#1012382).

  - input: ar1021_i2c - fix too long name in driver's device
    table (bsc#1031717).

  - input: edt-ft5x06 - fix setting gain, offset, and
    threshold via device tree (bsc#1031717).

  - input: elan_i2c - add ELAN060C to the ACPI table
    (bnc#1012382).

  - input: elan_i2c - add ELAN0611 to the ACPI table
    (bnc#1012382).

  - input: gtco - fix potential out-of-bound access
    (bnc#1012382).

  - input: mpr121 - handle multiple bits change of status
    register (bnc#1012382).

  - input: mpr121 - set missing event capability
    (bnc#1012382).

  - input: ti_am335x_tsc - fix incorrect step config for 5
    wire touchscreen (bsc#1031717).

  - input: twl4030-pwrbutton - use correct device for irq
    request (bsc#1031717).

  - input: ucb1400_ts - fix suspend and resume handling
    (bsc#1031717).

  - input: uinput - avoid crash when sending FF request to
    device going away (bsc#1031717).

  - iommu/amd: Finish TLB flush in amd_iommu_unmap()
    (bnc#1012382).

  - iommu/arm-smmu-v3: Clear prior settings when updating
    STEs (bnc#1012382).

  - iommu/vt-d: Do not register bus-notifier under
    dmar_global_lock (bsc#1069793).

  - ip6_gre: only increase err_count for some certain type
    icmpv6 in ip6gre_err (bnc#1012382).

  - ip6_gre: skb_push ipv6hdr before packing the header in
    ip6gre_header (bnc#1012382).

  - ipip: only increase err_count for some certain type icmp
    in ipip_err (bnc#1012382).

  - ipmi: fix unsigned long underflow (bnc#1012382).

  - ipmi: Pick up slave address from SMBIOS on an ACPI
    device (bsc#1070006).

  - ipmi: Prefer ACPI system interfaces over SMBIOS ones
    (bsc#1070006).

  - ipmi_si: Clean up printks (bsc#1070006).

  - ipmi_si: fix memory leak on new_smi (bsc#1070006).

  - ipsec: do not ignore crypto err in ah4 input
    (bnc#1012382).

  - ipv6: flowlabel: do not leave opt->tot_len with garbage
    (bnc#1012382).

  - ipv6: only call ip6_route_dev_notify() once for
    NETDEV_UNREGISTER (bnc#1012382).

  - ipvs: make drop_entry protection effective for SIP-pe
    (bsc#1056365).

  - irqchip/crossbar: Fix incorrect type of local variables
    (bnc#1012382).

  - isa: Prevent NULL dereference in isa_bus driver
    callbacks (bsc#1031717).

  - iscsi-target: Fix non-immediate TMR reference leak
    (bnc#1012382).

  - isdn/i4l: fetch the ppp_write buffer in one shot
    (bnc#1012382).

  - isofs: fix timestamps beyond 2027 (bnc#1012382).

  - iwlwifi: mvm: fix the coex firmware API (bsc#1031717).

  - iwlwifi: mvm: return -ENODATA when reading the
    temperature with the FW down (bsc#1031717).

  - iwlwifi: mvm: set the RTS_MIMO_PROT bit in flag mask
    when sending sta to fw (bsc#1031717).

  - iwlwifi: mvm: use IWL_HCMD_NOCOPY for MCAST_FILTER_CMD
    (bnc#1012382).

  - iwlwifi: split the regulatory rules when the bandwidth
    flags require it (bsc#1031717).

  - ixgbe: add mask for 64 RSS queues (bnc#1012382).

  - ixgbe: do not disable FEC from the driver (bnc#1012382).

  - ixgbe: fix AER error handling (bnc#1012382).

  - ixgbe: Fix skb list corruption on Power systems
    (bnc#1012382).

  - ixgbe: handle close/suspend race with
    netif_device_detach/present (bnc#1012382).

  - ixgbe: Reduce I2C retry count on X550 devices
    (bnc#1012382).

  - ixgbevf: Use smp_rmb rather than read_barrier_depends
    (bnc#1012382).

  - kABI fix for 4.4.99 net changes (stable-4.4.99).

  - kABI: protect struct l2tp_tunnel (kabi).

  - kABI: protect struct regulator_dev (kabi).

  - kABI: protect structs rt_rq+root_domain (kabi).

  - kABI: protect typedef rds_rdma_cookie_t (kabi).

  - kernel/sysctl.c: remove duplicate UINT_MAX check on
    do_proc_douintvec_conv() (bsc#1066470).

  - kernel/watchdog: Prevent false positives with turbo
    modes (bnc#1063516).

  - keys: do not let add_key() update an uninstantiated key
    (bnc#1012382).

  - keys: do not revoke uninstantiated key in
    request_key_auth_new() (bsc#1031717).

  - keys: encrypted: fix dereference of NULL
    user_key_payload (bnc#1012382).

  - keys: fix cred refcount leak in request_key_auth_new()
    (bsc#1031717).

  - keys: fix key refcount leak in keyctl_assume_authority()
    (bsc#1031717).

  - keys: fix key refcount leak in keyctl_read_key()
    (bsc#1031717).

  - keys: fix NULL pointer dereference during ASN.1 parsing
    [ver #2] (bnc#1012382).

  - keys: fix out-of-bounds read during ASN.1 parsing
    (bnc#1012382).

  - keys: Fix race between updating and finding a negative
    key (bnc#1012382).

  - keys: return full count in keyring_read() if buffer is
    too small (bnc#1012382).

  - keys: trusted: fix writing past end of buffer in
    trusted_read() (bnc#1012382).

  - keys: trusted: sanitize all key material (bnc#1012382).

  - KVM: nVMX: fix guest CR4 loading when emulating L2 to L1
    exit (bnc#1012382).

  - kvm: nVMX: set IDTR and GDTR limits when loading L1 host
    state (bnc#1012382).

  - KVM: PPC: Book 3S: XICS: correct the real mode ICP
    rejecting counter (bnc#1012382).

  - kvm: SVM: obey guest PAT (bnc#1012382).

  - l2tp: Avoid schedule while atomic in exit_net
    (bnc#1012382).

  - l2tp: check ps->sock before running
    pppol2tp_session_ioctl() (bnc#1012382).

  - l2tp: fix race condition in l2tp_tunnel_delete
    (bnc#1012382).

  - lib/digsig: fix dereference of NULL user_key_payload
    (bnc#1012382).

  - libertas: Fix lbs_prb_rsp_limit_set() (bsc#1031717).

  - lib/mpi: call cond_resched() from mpi_powm() loop
    (bnc#1012382).

  - libnvdimm, namespace: fix label initialization to use
    valid seq numbers (bnc#1012382).

  - libnvdimm, namespace: make 'resource' attribute only
    readable by root (bnc#1012382).

  - libnvdimm, pfn: make 'resource' attribute only readable
    by root (FATE#319858).

  - lib/ratelimit.c: use deferred printk() version
    (bsc#979928).

  - locking/lockdep: Add nest_lock integrity test
    (bnc#1012382).

  - mac80211: agg-tx: call drv_wake_tx_queue in proper
    context (bsc#1031717).

  - mac80211: do not compare TKIP TX MIC key in reinstall
    prevention (bsc#1066472).

  - mac80211: do not send SMPS action frame in AP mode when
    not needed (bsc#1031717).

  - mac80211: Fix addition of mesh configuration element
    (git-fixes).

  - mac80211: Fix BW upgrade for TDLS peers (bsc#1031717).

  - mac80211: fix mgmt-tx abort cookie and leak
    (bsc#1031717).

  - mac80211: fix power saving clients handling in iwlwifi
    (bnc#1012382).

  - mac80211_hwsim: check HWSIM_ATTR_RADIO_NAME length
    (bnc#1012382).

  - mac80211_hwsim: Fix memory leak in hwsim_new_radio_nl()
    (bsc#1031717).

  - mac80211: Remove invalid flag operations in mesh TSF
    synchronization (bnc#1012382).

  - mac80211: Remove unused 'beaconint_us' variable
    (bsc#1031717).

  - mac80211: Remove unused 'i' variable (bsc#1031717).

  - mac80211: Remove unused 'len' variable (bsc#1031717).

  - mac80211: Remove unused 'rates_idx' variable
    (bsc#1031717).

  - mac80211: Remove unused 'sband' and 'local' variables
    (bsc#1031717).

  - mac80211: Remove unused 'struct ieee80211_rx_status' ptr
    (bsc#1031717).

  - mac80211: Suppress NEW_PEER_CANDIDATE event if no room
    (bnc#1012382).

  - mac80211: TDLS: always downgrade invalid chandefs
    (bsc#1031717).

  - mac80211: TDLS: change BW calculation for WIDER_BW peers
    (bsc#1031717).

  - mac80211: use constant time comparison with keys
    (bsc#1066471).

  - md/linear: shutup lockdep warnning (bnc#1012382).

  - media: au0828: fix RC_CORE dependency (bsc#1031717).

  - media: Do not do DMA on stack for firmware upload in the
    AS102 driver (bnc#1012382).

  - media: em28xx: calculate left volume level correctly
    (bsc#1031717).

  - media: mceusb: fix memory leaks in error path
    (bsc#1031717).

  - media: rc: check for integer overflow (bnc#1012382).

  - media: v4l2-ctrl: Fix flags field on Control events
    (bnc#1012382).

  - megaraid_sas: Do not fire MR_DCMD_PD_LIST_QUERY to
    controllers which do not support it (bsc#1027301).

  - mei: return error on notification request to a
    disconnected client (bnc#1012382).

  - mfd: ab8500-sysctrl: Handle probe deferral
    (bnc#1012382).

  - mfd: axp20x: Fix axp288 PEK_DBR and PEK_DBF irqs being
    swapped (bnc#1012382).

  - mips: AR7: Defer registration of GPIO (bnc#1012382).

  - mips: AR7: Ensure that serial ports are properly set up
    (bnc#1012382).

  - mips: BCM47XX: Fix LED inversion for WRT54GSv1
    (bnc#1012382).

  - mips: End asm function prologue macros with .insn
    (bnc#1012382).

  - mips: Fix an n32 core file generation regset support
    regression (bnc#1012382).

  - mips: Fix CM region target definitions (bnc#1012382).

  - mips: Fix race on setting and getting cpu_online_mask
    (bnc#1012382).

  - mips: init: Ensure bootmem does not corrupt reserved
    memory (bnc#1012382).

  - mips: init: Ensure reserved memory regions are not added
    to bootmem (bnc#1012382).

  - mips: math-emu: Remove pr_err() calls from fpu_emu()
    (bnc#1012382).

  - mips: microMIPS: Fix incorrect mask in insn_table_MM
    (bnc#1012382).

  - mips: Netlogic: Exclude netlogic,xlp-pic code from XLR
    builds (bnc#1012382).

  - mips: ralink: Fix MT7628 pinmux (bnc#1012382).

  - mips: ralink: Fix typo in mt7628 pinmux function
    (bnc#1012382).

  - mips: SMP: Fix deadlock & online race (bnc#1012382).

  - mips: SMP: Use a completion event to signal CPU up
    (bnc#1012382).

  - misc: panel: properly restore atomic counter on error
    path (bnc#1012382).

  - mmc: block: return error on failed mmc_blk_get()
    (bsc#1031717).

  - mmc: core/mmci: restore pre/post_req behaviour
    (bsc#1031717).

  - mmc: dw_mmc: rockchip: Set the drive phase properly
    (bsc#1031717).

  - mm: check the return value of lookup_page_ext for all
    call sites (bnc#1068982).

  - mmc: host: omap_hsmmc: avoid possible overflow of
    timeout value (bsc#1031717).

  - mmc: host: omap_hsmmc: checking for NULL instead of
    IS_ERR() (bsc#1031717).

  - mmc: mediatek: Fixed size in dma_free_coherent
    (bsc#1031717).

  - mmc: s3cmci: include linux/interrupt.h for
    tasklet_struct (bnc#1012382).

  - mmc: sd: limit SD card power limit according to cards
    capabilities (bsc#1031717).

  - mm, hwpoison: fixup 'mm: check the return value of
    lookup_page_ext for all call sites' (bnc#1012382).

  - mm/madvise.c: fix madvise() infinite loop under special
    circumstances (bnc#1070964).

  - mm/page_alloc.c: broken deferred calculation
    (bnc#1068980).

  - mm, page_alloc: fix potential false positive in
    __zone_watermark_ok (Git-fixes, bsc#1068978).

  - mm/page_ext.c: check if page_ext is not prepared
    (bnc#1068982).

  - mm/page_owner: avoid NULL pointer dereference
    (bnc#1068982).

  - mm/pagewalk.c: report holes in hugetlb ranges
    (bnc#1012382).

  - net: 3com: typhoon: typhoon_init_one: fix incorrect
    return values (bnc#1012382).

  - net: 3com: typhoon: typhoon_init_one: make return values
    more specific (bnc#1012382).

  - net/9p: Switch to wait_event_killable() (bnc#1012382).

  - net: Allow IP_MULTICAST_IF to set index to L3 slave
    (bnc#1012382).

  - net: cdc_ether: fix divide by 0 on bad descriptors
    (bnc#1012382).

  - net: cdc_ncm: GetNtbFormat endian fix (git-fixes).

  - net: dsa: select NET_SWITCHDEV (bnc#1012382).

  - net: emac: Fix napi poll list corruption (bnc#1012382).

  - netfilter/ipvs: clear ipvs_property flag when SKB net
    namespace changed (bnc#1012382).

  - netfilter: nf_ct_expect: Change __nf_ct_expect_check()
    return value (bnc#1012382).

  - netfilter: nf_tables: fix oob access (bnc#1012382).

  - netfilter: nft_meta: deal with PACKET_LOOPBACK in netdev
    family (bnc#1012382).

  - netfilter: nft_queue: use raw_smp_processor_id()
    (bnc#1012382).

  - net: ibm: ibmvnic: constify vio_device_id (fate#323285).

  - net/mlx4_core: Fix VF overwrite of module param which
    disables DMFS on new probed PFs (bnc#1012382).

  - net/mlx4_en: fix overflow in mlx4_en_init_timestamp()
    (bnc#1012382).

  - net: mvpp2: release reference to txq_cpu[] entry after
    unmapping (bnc#1012382).

  - net: qmi_wwan: fix divide by 0 on bad descriptors
    (bnc#1012382).

  - net/sctp: Always set scope_id in sctp_inet6_skb_msgname
    (bnc#1012382).

  - net: Set sk_prot_creator when cloning sockets to the
    right proto (bnc#1012382).

  - net/unix: do not show information about sockets from
    other namespaces (bnc#1012382).

  - nfc: fix device-allocation error return (bnc#1012382).

  - nfsd/callback: Cleanup callback cred on shutdown
    (bnc#1012382).

  - nfsd: deal with revoked delegations appropriately
    (bnc#1012382).

  - nfs: Do not disconnect open-owner on NFS4ERR_BAD_SEQID
    (bsc#989261).

  - nfs: Fix typo in nomigration mount option (bnc#1012382).

  - nfs: Fix ugly referral attributes (bnc#1012382).

  - nilfs2: fix race condition that causes file system
    corruption (bnc#1012382).

  - nl80211: Define policy for packet pattern attributes
    (bnc#1012382).

  - nvme: Fix memory order on async queue deletion
    (bnc#1012382).

  - ocfs2: fstrim: Fix start offset of first cluster group
    during fstrim (bnc#1012382).

  - ocfs2: should wait dio before inode lock in
    ocfs2_setattr() (bnc#1012382).

  - packet: avoid panic in packet_getsockopt()
    (bnc#1012382).

  - packet: only test po->has_vnet_hdr once in packet_snd
    (bnc#1012382).

  - parisc: Avoid trashing sr2 and sr3 in LWS code
    (bnc#1012382).

  - parisc: Fix double-word compare and exchange in LWS code
    on 32-bit kernels (bnc#1012382).

  - parisc: Fix validity check of pointer size argument in
    new CAS implementation (bnc#1012382).

  - pci: Apply _HPX settings only to relevant devices
    (bnc#1012382).

  - pci: mvebu: Handle changes to the bridge windows while
    enabled (bnc#1012382).

  - percpu: make this_cpu_generic_read() atomic w.r.t.
    interrupts (bnc#1012382).

  - perf tools: Fix build failure on perl script context
    (bnc#1012382).

  - perf tools: Only increase index if perf_evsel__new_idx()
    succeeds (bnc#1012382).

  - perf/x86/intel/bts: Fix exclusive event reference leak
    (git-fixes d2878d642a4ed).

  - phy: increase size of MII_BUS_ID_SIZE and bus_id
    (bnc#1012382).

  - pkcs#7: fix uninitialized boolean 'want' (bnc#1012382).

  - pkcs7: Prevent NULL pointer dereference, since sinfo is
    not always set (bnc#1012382).

  - platform/x86: acer-wmi: setup accelerometer when ACPI
    device was found (bsc#1031717).

  - platform/x86: hp-wmi: Do not shadow error values
    (bnc#1012382).

  - platform/x86: hp-wmi: Fix detection for dock and tablet
    mode (bnc#1012382).

  - platform/x86: hp-wmi: Fix error value for
    hp_wmi_tablet_state (bnc#1012382).

  - platform/x86: intel_mid_thermal: Fix module autoload
    (bnc#1012382).

  - platform/x86: sony-laptop: Fix error handling in
    sony_nc_setup_rfkill() (bsc#1031717).

  - pm / OPP: Add missing of_node_put(np) (bnc#1012382).

  - power: bq27xxx_battery: Fix bq27541 AveragePower
    register address (bsc#1031717).

  - power: bq27xxx: fix reading for bq27000 and bq27010
    (bsc#1031717).

  - powercap: Fix an error code in powercap_register_zone()
    (bsc#1031717).

  - power: ipaq-micro-battery: freeing the wrong variable
    (bsc#1031717).

  - powerpc/64: Fix race condition in setting lock bit in
    idle/wakeup code (bsc#1066223).

  - powerpc/bpf/jit: Disable classic BPF JIT on ppc64le
    (bsc#1066223).

  - powerpc/corenet: explicitly disable the SDHC controller
    on kmcoge4 (bnc#1012382).

  - powerpc: Correct instruction code for xxlor instruction
    (bsc#1066223).

  - powerpc: Fix VSX enabling/flushing to also test MSR_FP
    and MSR_VEC (bsc#1066223).

  - powerpc/mm: Fix check of multiple 16G pages from device
    tree (bsc#1066223).

  - powerpc/mm: Fix virt_addr_valid() etc. on 64-bit hash
    (bsc#1066223).

  - powerpc/mm/hash64: Fix subpage protection with 4K HPTE
    config (bsc#1010201, bsc#1066223).

  - powerpc/mm/hash: Free the subpage_prot_table correctly
    (bsc#1066223).

  - powerpc/numa: Fix multiple bugs in memory_hotplug_max()
    (bsc#1066223).

  - powerpc/numa: Fix whitespace in
    hot_add_drconf_memory_max() (bsc#1066223).

  - powerpc/opal: Fix EBUSY bug in acquiring tokens
    (bsc#1066223).

  - powerpc/perf: Remove PPMU_HAS_SSLOT flag for Power8
    (bsc#1066223).

  - powerpc/powernv/ioda: Fix endianness when reading TCEs
    (bsc#1066223).

  - powerpc/powernv: Make opal_event_shutdown() callable
    from IRQ context (bsc#1066223).

  - powerpc/pseries/vio: Dispose of virq mapping on vdevice
    unregister (bsc#1067888).

  - powerpc/signal: Properly handle return value from
    uprobe_deny_signal() (bsc#1066223).

  - powerpc/sysrq: Fix oops whem ppmu is not registered
    (bsc#1066223).

  - power: supply: bq27xxx_battery: Fix register map for
    BQ27510 and BQ27520 ('bsc#1069270').

  - power: supply: isp1704: Fix unchecked return value of
    devm_kzalloc (bsc#1031717).

  - power: supply: lp8788: prevent out of bounds array
    access (bsc#1031717).

  - power_supply: tps65217-charger: Fix NULL deref during
    property export (bsc#1031717).

  - ppp: fix race in ppp device destruction (bnc#1012382).

  - printk/console: Always disable boot consoles that use
    init memory before it is freed (bsc#1063026).

  - printk/console: Enhance the check for consoles using
    init memory (bsc#1063026).

  - printk: include <asm/sections.h> instead of
    <asm-generic/sections.h> (bsc#1063026).

  - printk: only unregister boot consoles when necessary
    (bsc#1063026).

  - quota: Check for register_shrinker() failure
    (bsc#1012829).

  - r8169: Do not increment tx_dropped in TX ring cleaning
    (bsc#1031717).

  - rbd: use GFP_NOIO for parent stat and data requests
    (bnc#1012382).

  - rcu: Allow for page faults in NMI handlers
    (bnc#1012382).

  - rdma/uverbs: Prevent leak of reserved field (bsc#1022595
    FATE#322350).

  - rds: RDMA: return appropriate error on rdma map failures
    (bnc#1012382).

  - regulator: core: Limit propagation of parent voltage
    count and list (bsc#1070145).

  - regulator: fan53555: fix I2C device ids (bnc#1012382).

  - Revert 'bpf: one perf event close won't free bpf program
    attached by another perf event' (kabi).

  - Revert 'bsg-lib: do not free job in bsg_prepare_job'
    (bnc#1012382).

  - Revert 'crypto: xts - Add ECB dependency' (bnc#1012382).

  - Revert 'drm: bridge: add DT bindings for TI ths8135'
    (bnc#1012382).

  - Revert 'keys: Fix race between updating and finding a
    negative key' (kabi).

  - Revert 'phy: increase size of MII_BUS_ID_SIZE and
    bus_id' (kabi).

  - Revert 'sctp: do not peel off an assoc from one netns to
    another one' (bnc#1012382).

  - Revert 'tty: goldfish: Fix a parameter of a call to
    free_irq' (bnc#1012382).

  - Revert 'uapi: fix linux/rds.h userspace compilation
    errors' (bnc#1012382).

  - rpm/kernel-binary.spec.in: add the kernel-binary
    dependencies to kernel-binary-base (bsc#1060333).

  - rpm/kernel-binary.spec.in: Correct supplements for
    recent SLE products (bsc#1067494)

  - rpm/kernel-binary.spec.in: only rewrite modules.dep if
    non-zero in size (bsc#1056979).

  - rtc: ds1307: Fix relying on reset value for weekday
    (bsc#1031717).

  - rtc: ds1374: wdt: Fix issue with timeout scaling from
    secs to wdt ticks (bsc#1031717).

  - rtc: ds1374: wdt: Fix stop/start ioctl always returning
    -EINVAL (bsc#1031717).

  - rtc: rtc-nuc900: fix loop timeout test (bsc#1031717).

  - rtc: sa1100: fix unbalanced
    clk_prepare_enable/clk_disable_unprepare (bsc#1031717).

  - rtlwifi: fix uninitialized rtlhal->last_suspend_sec time
    (bnc#1012382).

  - rtlwifi: rtl8192ee: Fix memory leak when loading
    firmware (bnc#1012382).

  - rtlwifi: rtl8821ae: Fix connection lost problem
    (bnc#1012382).

  - rtlwifi: rtl8821ae: Fix HW_VAR_NAV_UPPER operation
    (bsc#1031717).

  - s390/dasd: check for device error pointer within state
    change interrupts (bnc#1012382).

  - s390/disassembler: add missing end marker for e7 table
    (bnc#1012382).

  - s390/disassembler: correct disassembly lines alignment
    (bsc#1070825).

  - s390/disassembler: increase show_code buffer size
    (bnc#1012382).

  - s390: fix transactional execution control register
    handling (bnc#1012382).

  - s390/kbuild: enable modversions for symbols exported
    from asm (bnc#1012382).

  - s390/qeth: issue STARTLAN as first IPA command
    (bnc#1012382).

  - s390/runtime instrumention: fix possible memory
    corruption (bnc#1012382).

  - sched/autogroup: Fix autogroup_move_group() to never
    skip sched_move_task() (bnc#1012382).

  - sched: Make resched_cpu() unconditional (bnc#1012382).

  - sched/rt: Simplify the IPI based RT balancing logic
    (bnc#1012382).

  - scsi: aacraid: Process Error for response I/O
    (bnc#1012382).

  - scsi_devinfo: cleanly zero-pad devinfo strings
    (bsc#1062941).

  - scsi: ipr: Fix scsi-mq lockdep issue (bsc#1066213).

  - scsi: ipr: Set no_report_opcodes for RAID arrays
    (bsc#1066213).

  - scsi: libiscsi: fix shifting of DID_REQUEUE host byte
    (bsc#1056003).

  - scsi: lpfc: Add missing memory barrier (bnc#1012382).

  - scsi: lpfc: Clear the VendorVersion in the PLOGI/PLOGI
    ACC payload (bnc#1012382).

  - scsi: lpfc: Correct host name in symbolic_name field
    (bnc#1012382).

  - scsi: lpfc: Correct issue leading to oops during link
    reset (bnc#1012382).

  - scsi: lpfc: FCoE VPort enable-disable does not bring up
    the VPort (bnc#1012382).

  - scsi: reset wait for IO completion (bsc#996376).

  - scsi: scsi_devinfo: fixup string compare (bsc#1062941).
    updated
    patches.fixes/scsi_devinfo-fixup-string-compare.patch to
    the version merged upstream.

  - scsi: scsi_devinfo: handle non-terminated strings
    (bsc#1062941).

  - scsi: scsi_dh_emc: return success in
    clariion_std_inquiry() (bnc#1012382).

  - scsi: scsi_transport_fc: Also check for NOTPRESENT in
    fc_remote_port_add() (bsc#1037890).

  - scsi: scsi_transport_fc: set scsi_target_id upon rescan
    (bsc#1058135).

  - scsi: sg: Re-fix off by one in sg_fill_request_table()
    (bnc#1012382).

  - scsi: ufs: add capability to keep auto bkops always
    enabled (bnc#1012382).

  - scsi: ufs-qcom: Fix module autoload (bnc#1012382).

  - scsi: virtio_scsi: let host do exception handling
    (bsc#1060682).

  - scsi: zfcp: fix erp_action use-before-initialize in REC
    action trace (bnc#1012382).

  - sctp: add the missing sock_owned_by_user check in
    sctp_icmp_redirect (bnc#1012382).

  - sctp: do not peel off an assoc from one netns to another
    one (bnc#1012382).

  - sctp: potential read out of bounds in
    sctp_ulpevent_type_enabled() (bnc#1012382).

  - sctp: reset owner sk for data chunks on out queues when
    migrating a sock (bnc#1012382).

  - security/keys: add CONFIG_KEYS_COMPAT to Kconfig
    (bnc#1012382).

  - selftests: firmware: add empty string and async tests
    (bnc#1012382).

  - selftests: firmware: send expected errors to /dev/null
    (bnc#1012382).

  - serial: 8250_fintek: Fix rs485 disablement on invalid
    ioctl() (bsc#1031717).

  - serial: 8250_uniphier: fix serial port index in private
    data (bsc#1031717).

  - serial: Fix serial console on SNI RM400 machines
    (bsc#1031717).

  - serial: omap: Fix EFR write on RTS deassertion
    (bnc#1012382).

  - serial: Remove unused port type (bsc#1066045).

  - serial: sh-sci: Fix register offsets for the IRDA serial
    port (bnc#1012382).

  - slub: do not merge cache if slub_debug contains a
    never-merge flag (bnc#1012382).

  - smb3: parsing for new snapshot timestamp mount parm
    (FATE#324404). New mount option 'snapshot=<time>' to
    allow mounting an earlier version of the remote volume
    (if such a snapshot exists on the server). Note that
    eventually specifying a snapshot time of 1 will allow
    the user to mount the oldest snapshot. A subsequent
    patch add the processing for that and another for
    actually specifying the 'time warp' create context on
    SMB2/SMB3 open. Check to make sure SMB2 negotiated, and
    ensure that we use a different tcon if mount same share
    twice but with different snaphshot times

  - sparc64: Migrate hvcons irq to panicked cpu
    (bnc#1012382).

  - spi: SPI_FSL_DSPI should depend on HAS_DMA
    (bnc#1012382).

  - spi: uapi: spidev: add missing ioctl header
    (bnc#1012382).

  - staging: iio: cdc: fix improper return value
    (bnc#1012382).

  - staging: lustre: hsm: stack overrun in
    hai_dump_data_field (bnc#1012382).

  - staging: lustre: llite: do not invoke direct_IO for the
    EOF case (bnc#1012382).

  - staging: lustre: ptlrpc: skip lock if export failed
    (bnc#1012382).

  - staging: r8712u: Fix Sparse warning in rtl871x_xmit.c
    (bnc#1012382).

  - staging: rtl8188eu: fix incorrect ERROR tags from logs
    (bnc#1012382).

  - staging: rtl8712: fixed little endian problem
    (bnc#1012382).

  - staging: rtl8712u: Fix endian settings for structs
    describing network packets (bnc#1012382).

  - sunrpc: Fix tracepoint storage issues with svc_recv and
    svc_rqst_status (bnc#1012382).

  - target: fix ALUA state file path truncation
    (bsc#1071231).

  - target: Fix node_acl demo-mode + uncached dynamic
    shutdown regression (bnc#1012382).

  - target: fix PR state file path truncation (bsc#1071231).

  - target: Fix QUEUE_FULL + SCSI task attribute handling
    (bnc#1012382).

  - target/iscsi: Fix iSCSI task reassignment handling
    (bnc#1012382).

  - target/iscsi: Fix unsolicited data seq_end_offset
    calculation (bnc#1012382).

  - tcp/dccp: fix ireq->opt races (bnc#1012382).

  - tcp/dccp: fix lockdep splat in inet_csk_route_req()
    (bnc#1012382).

  - tcp/dccp: fix other lockdep splats accessing ireq_opt
    (bnc#1012382).

  - tcp: do not mangle skb->cb[] in tcp_make_synack()
    (bnc#1012382).

  - tcp: fix tcp_mtu_probe() vs highest_sack (bnc#1012382).

  - test: firmware_class: report errors properly on failure
    (bnc#1012382).

  - timer: Prevent timer value 0 for MWAITX (bsc#1065717).

  - tipc: fix link attribute propagation bug (bnc#1012382).

  - tipc: use only positive error codes in messages
    (bnc#1012382).

  - tools: firmware: check for distro fallback udev cancel
    rule (bnc#1012382).

  - tracing/samples: Fix creation and deletion of
    simple_thread_fn creation (bnc#1012382).

  - tun: allow positive return values on
    dev_get_valid_name() call (bnc#1012382).

  - tun: bail out from tun_get_user() if the skb is empty
    (bnc#1012382).

  - tun: call dev_get_valid_name() before
    register_netdevice() (bnc#1012382).

  - tun/tap: sanitize TUNSETSNDBUF input (bnc#1012382).

  - uapi: fix linux/mroute6.h userspace compilation errors
    (bnc#1012382).

  - uapi: fix linux/rds.h userspace compilation error
    (bnc#1012382).

  - uapi: fix linux/rds.h userspace compilation errors
    (bnc#1012382).

  - udpv6: Fix the checksum computation when HW checksum
    does not apply (bnc#1012382).

  - usb: Add delay-init quirk for Corsair K70 LUX keyboards
    (bnc#1012382).

  - usb: cdc_acm: Add quirk for Elatec TWN3 (bnc#1012382).

  - usb: core: fix out-of-bounds access bug in
    usb_get_bos_descriptor() (bnc#1012382).

  - usb: devio: Revert 'USB: devio: Do not corrupt user
    memory' (bnc#1012382).

  - usb: dummy-hcd: Fix deadlock caused by disconnect
    detection (bnc#1012382).

  - usb: gadget: composite: Fix use-after-free in
    usb_composite_overwrite_options (bnc#1012382).

  - usb: hcd: initialize hcd->flags to 0 when rm hcd
    (bnc#1012382).

  - usb: hub: Allow reset retry for USB2 devices on connect
    bounce (bnc#1012382).

  - usb: musb: Check for host-mode using is_host_active() on
    reset interrupt (bnc#1012382).

  - usb: musb: sunxi: Explicitly release USB PHY on exit
    (bnc#1012382).

  - usb: quirks: add quirk for WORLDE MINI MIDI keyboard
    (bnc#1012382).

  - usb: renesas_usbhs: Fix DMAC sequence for receiving
    zero-length packet (bnc#1012382).

  - usb: serial: console: fix use-after-free after failed
    setup (bnc#1012382).

  - usb: serial: cp210x: add support for ELV TFD500
    (bnc#1012382).

  - usb: serial: ftdi_sio: add id for Cypress WICED dev
    board (bnc#1012382).

  - usb: serial: garmin_gps: fix I/O after failed probe and
    remove (bnc#1012382).

  - usb: serial: garmin_gps: fix memory leak on probe errors
    (bnc#1012382).

  - usb: serial: metro-usb: add MS7820 device id
    (bnc#1012382).

  - usb: serial: option: add support for TP-Link LTE module
    (bnc#1012382).

  - usb: serial: qcserial: add Dell DW5818, DW5819
    (bnc#1012382).

  - usb: serial: qcserial: add pid/vid for Sierra Wireless
    EM7355 fw update (bnc#1012382).

  - usb: usbfs: compute urb->actual_length for isochronous
    (bnc#1012382).

  - usb: usbtest: fix NULL pointer dereference
    (bnc#1012382).

  - usb: xhci: Handle error condition in xhci_stop_device()
    (bnc#1012382).

  - vfs: expedite unmount (bsc#1024412).

  - video: fbdev: pmag-ba-fb: Remove bad `__init' annotation
    (bnc#1012382).

  - video: udlfb: Fix read EDID timeout (bsc#1031717).

  - vlan: fix a use-after-free in vlan_device_event()
    (bnc#1012382).

  - vsock: use new wait API for vsock_stream_sendmsg()
    (bnc#1012382).

  - vti: fix use after free in vti_tunnel_xmit/vti6_tnl_xmit
    (bnc#1012382).

  - watchdog: kempld: fix gcc-4.3 build (bnc#1012382).

  - workqueue: Fix NULL pointer dereference (bnc#1012382).

  - workqueue: replace pool->manager_arb mutex with a flag
    (bnc#1012382).

  - x86/alternatives: Fix alt_max_short macro to really be a
    max() (bnc#1012382).

  - x86/decoder: Add new TEST instruction pattern
    (bnc#1012382).

  - x86/MCE/AMD: Always give panic severity for UC errors in
    kernel context (git-fixes bf80bbd7dcf5).

  - x86/microcode/AMD: Add support for fam17h microcode
    loading (bsc#1068032).

  - x86/microcode/intel: Disable late loading on model 79
    (bnc#1012382).

  - x86/oprofile/ppro: Do not use __this_cpu*() in
    preemptible context (bnc#1012382).

  - x86/uaccess, sched/preempt: Verify access_ok() context
    (bnc#1012382).

  - xen: do not print error message in case of missing
    Xenstore entry (bnc#1012382).

  - xen/events: events_fifo: Do not use (get,put)_cpu() in
    xen_evtchn_fifo_init() (bnc#1065600).

  - xen: fix booting ballooned down hvm guest (bnc#1065600).

  - xen/gntdev: avoid out of bounds access in case of
    partial gntdev_mmap() (bnc#1012382).

  - xen/manage: correct return value check on xenbus_scanf()
    (bnc#1012382).

  - xen-netback: fix error handling output (bnc#1065600).

  - xen: x86: mark xen_find_pt_base as __init (bnc#1065600).

  - xen: xenbus driver must not accept invalid transaction
    ids (bnc#1012382).

  - zd1211rw: fix NULL-deref at probe (bsc#1031717)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=996376"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.103-18.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.103-18.41.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-docs-html / kernel-docs-pdf / kernel-devel / kernel-macros / etc");
}
