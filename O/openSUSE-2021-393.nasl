#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-393.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(147563);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2020-12362",
    "CVE-2020-12363",
    "CVE-2020-12364",
    "CVE-2020-12373",
    "CVE-2020-29368",
    "CVE-2020-29374",
    "CVE-2021-26930",
    "CVE-2021-26931",
    "CVE-2021-26932"
  );

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2021-393)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The openSUSE Linux Leap 15.2 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2021-26930: Fixed an improper error handling in
    blkback's grant mapping (XSA-365 bsc#1181843).

  - CVE-2021-26931: Fixed an issue where Linux kernel was
    treating grant mapping errors as bugs (XSA-362
    bsc#1181753).

  - CVE-2021-26932: Fixed improper error handling issues in
    Linux grant mapping (XSA-361 bsc#1181747). by remote
    attackers to read or write files via directory traversal
    in an XCOPY request (bsc#178372).

  - CVE-2020-12362: Fixed an integer overflow in the
    firmware which may have allowed a privileged user to
    potentially enable an escalation of privilege via local
    access (bsc#1181720).

  - CVE-2020-12363: Fixed an improper input validation which
    may have allowed a privileged user to potentially enable
    a denial of service via local access (bsc#1181735).

  - CVE-2020-12364: Fixed a NULL pointer reference which may
    have allowed a privileged user to potentially enable a
    denial of service via local access (bsc#1181736 ).

  - CVE-2020-12373: Fixed an expired pointer dereference
    which may have allowed a privileged user to potentially
    enable a denial of service via local access
    (bsc#1181738).

  - CVE-2020-29368,CVE-2020-29374: Fixed an issue in
    copy-on-write implementation which could have granted
    unintended write access because of a race condition in a
    THP mapcount check (bsc#1179660, bsc#1179428).

The following non-security bugs were fixed :

  - ACPICA: Fix exception code class checks (git-fixes).

  - ACPI: configfs: add missing check after
    configfs_register_default_group() (git-fixes).

  - ACPI: property: Fix fwnode string properties matching
    (git-fixes).

  - ACPI: property: Satisfy kernel doc validator (part 1)
    (git-fixes).

  - ACPI: property: Satisfy kernel doc validator (part 2)
    (git-fixes).

  - ALSA: hda: Add another CometLake-H PCI ID (git-fixes).

  - ALSA: hda/hdmi: Drop bogus check at closing a stream
    (git-fixes).

  - ALSA: hda/realtek: modify EAPD in the ALC886
    (git-fixes).

  - ALSA: pcm: Assure sync with the pending stop operation
    at suspend (git-fixes).

  - ALSA: pcm: Call sync_stop at disconnection (git-fixes).

  - ALSA: pcm: Do not call sync_stop if it hasn't been
    stopped (git-fixes).

  - ALSA: usb-audio: Add implicit fb quirk for BOSS GP-10
    (git-fixes).

  - ALSA: usb-audio: Correct document for
    snd_usb_endpoint_free_all() (git-fixes).

  - ALSA: usb-audio: Do not avoid stopping the stream at
    disconnection (git-fixes).

  - ALSA: usb-audio: Fix PCM buffer allocation in
    non-vmalloc mode (git-fixes).

  - ALSA: usb-audio: Handle invalid running state at
    releasing EP (git-fixes).

  - ALSA: usb-audio: More strict state change in EP
    (git-fixes).

  - amba: Fix resource leak for drivers without .remove
    (git-fixes).

  - arm64: Update config file. Set CONFIG_WATCHDOG_SYSFS to
    true (bsc#1182560)

  - armv7hl: lpae: Update config files. Disable KVM support
    (bsc#1182697)

  - ASoC: cpcap: fix microphone timeslot mask (git-fixes).

  - ASoC: cs42l56: fix up error handling in probe
    (git-fixes).

  - ASoC: simple-card-utils: Fix device module clock
    (git-fixes).

  - ASoC: SOF: debug: Fix a potential issue on string buffer
    termination (git-fixes).

  - ata: ahci_brcm: Add back regulators management
    (git-fixes).

  - ata: sata_nv: Fix retrieving of active qcs (git-fixes).

  - ath10k: Fix error handling in case of CE pipe init
    failure (git-fixes).

  - ath9k: fix data bus crash when setting nf_override via
    debugfs (git-fixes).

  - bcache: fix overflow in offset_to_stripe() (git-fixes).

  - blk-mq: call commit_rqs while list empty but error
    happen (bsc#1182442).

  - blk-mq: insert request not through ->queue_rq into
    sw/scheduler queue (bsc#1182443).

  - blk-mq: move cancel of hctx->run_work to the front of
    blk_exit_queue (bsc#1182444).

  - block: fix inflight statistics of part0 (bsc#1182445).

  - block: respect queue limit of max discard segment
    (bsc#1182441).

  - block: virtio_blk: fix handling single range discard
    request (bsc#1182439).

  - Bluetooth: btqcomsmd: Fix a resource leak in error
    handling paths in the probe function (git-fixes).

  - Bluetooth: btusb: Fix memory leak in btusb_mtk_wmt_recv
    (git-fixes).

  - Bluetooth: drop HCI device reference before return
    (git-fixes).

  - Bluetooth: Fix initializing response id after clearing
    struct (git-fixes).

  - Bluetooth: hci_uart: Fix a race for write_work
    scheduling (git-fixes).

  - Bluetooth: Put HCI device if inquiry procedure
    interrupts (git-fixes).

  - bnxt_en: Fix accumulation of bp->net_stats_prev
    (git-fixes).

  - bnxt_en: fix error return code in bnxt_init_board()
    (git-fixes).

  - bnxt_en: fix error return code in bnxt_init_one()
    (git-fixes).

  - bnxt_en: Improve stats context resource accounting with
    RDMA driver loaded (git-fixes).

  - bnxt_en: read EEPROM A2h address using page 0
    (git-fixes).

  - bnxt_en: Release PCI regions when DMA mask setup fails
    during probe (git-fixes).

  - bonding: Fix reference count leak in
    bond_sysfs_slave_add (git-fixes).

  - bonding: set dev->needed_headroom in
    bond_setup_by_slave() (git-fixes).

  - bonding: wait for sysfs kobject destruction before
    freeing struct slave (git-fixes).

  - bpf, cgroup: Fix optlen WARN_ON_ONCE toctou
    (bsc#1155518).

  - bpf, cgroup: Fix problematic bounds check (bsc#1155518).

  - btrfs: add assertion for empty list of transactions at
    late stage of umount (bsc#1182626).

  - btrfs: Cleanup try_flush_qgroup (bsc#1182047).

  - btrfs: Do not flush from
    btrfs_delayed_inode_reserve_metadata (bsc#1182047).

  - btrfs: Fix race between extent freeing/allocation when
    using bitmaps (bsc#1181574).

  - btrfs: fix race between RO remount and the cleaner task
    (bsc#1182626).

  - btrfs: fix transaction leak and crash after cleaning up
    orphans on RO mount (bsc#1182626).

  - btrfs: fix transaction leak and crash after RO remount
    caused by qgroup rescan (bsc#1182626).

  - btrfs: Free correct amount of space in
    btrfs_delayed_inode_reserve_metadata (bsc#1182047).

  - btrfs: lift read-write mount setup from mount and
    remount (bsc#1182626).

  - btrfs: Remove btrfs_inode from
    btrfs_delayed_inode_reserve_metadata (bsc#1182047).

  - btrfs: run delayed iputs when remounting RO to avoid
    leaking them (bsc#1182626).

  - btrfs: Simplify code flow in
    btrfs_delayed_inode_reserve_metadata (bsc#1182047).

  - btrfs: Unlock extents in btrfs_zero_range in case of
    errors (bsc#1182047).

  - caif: no need to check return value of debugfs_create
    functions (git-fixes).

  - ceph: fix flush_snap logic after putting caps
    (bsc#1182854).

  - cgroup: Fix memory leak when parsing multiple source
    parameters (bsc#1182683).

  - cgroup: fix psi monitor for root cgroup (bsc#1182686).

  - cgroup-v1: add disabled controller check in
    cgroup1_parse_param() (bsc#1182684).

  - chelsio/chtls: correct function return and return type
    (git-fixes).

  - chelsio/chtls: correct netdevice for vlan interface
    (git-fixes).

  - chelsio/chtls: fix a double free in chtls_setkey()
    (git-fixes).

  - chelsio/chtls: fix always leaking ctrl_skb (git-fixes).

  - chelsio/chtls: fix deadlock issue (git-fixes).

  - chelsio/chtls: fix memory leaks caused by a race
    (git-fixes).

  - chelsio/chtls: fix memory leaks in CPL handlers
    (git-fixes).

  - chelsio/chtls: fix panic during unload reload chtls
    (git-fixes).

  - chelsio/chtls: fix socket lock (git-fixes).

  - chelsio/chtls: fix tls record info to user (git-fixes).

  - Cherry-pick ibmvnic patches from SP3 (jsc#SLE-17268).

  - chtls: Added a check to avoid NULL pointer dereference
    (git-fixes).

  - chtls: Fix chtls resources release sequence (git-fixes).

  - chtls: Fix hardware tid leak (git-fixes).

  - chtls: Fix panic when route to peer not configured
    (git-fixes).

  - chtls: Remove invalid set_tcb call (git-fixes).

  - chtls: Replace skb_dequeue with skb_peek (git-fixes).

  - cifs: check all path components in resolved dfs target
    (bsc#1181710).

  - cifs: fix nodfs mount option (bsc#1181710).

  - cifs: introduce helper for finding referral server
    (bsc#1181710).

  - cifs: report error instead of invalid when revalidating
    a dentry fails (bsc#1177440).

  - cirrus: cs89x0: remove set but not used variable 'lp'
    (git-fixes).

  - cirrus: cs89x0: use devm_platform_ioremap_resource() to
    simplify code (git-fixes).

  - clk: meson: clk-pll: fix initializing the old rate
    (fallback) for a PLL (git-fixes).

  - clk: meson: clk-pll: make 'ret' a signed integer
    (git-fixes).

  - clk: meson: clk-pll: propagate the error from
    meson_clk_pll_set_rate() (git-fixes).

  - clk: qcom: gcc-msm8998: Fix Alpha PLL type for all GPLLs
    (git-fixes).

  - clk: sunxi-ng: h6: Fix CEC clock (git-fixes).

  - clk: sunxi-ng: h6: Fix clock divider range on some
    clocks (git-fixes).

  - clk: sunxi-ng: mp: fix parent rate change flag check
    (git-fixes).

  - clocksource/drivers/ixp4xx: Select TIMER_OF when needed
    (git-fixes).

  - cpufreq: brcmstb-avs-cpufreq: Fix resource leaks in
    ->remove() (git-fixes).

  - cpufreq: brcmstb-avs-cpufreq: Free resources in error
    path (git-fixes).

  - cpuset: fix race between hotplug work and later CPU
    offline (bsc#1182676).

  - crypto: ecdh_helper - Ensure 'len >= secret.len' in
    decode_key() (git-fixes).

  - crypto: talitos - Work around SEC6 ERRATA (AES-CTR mode
    data size error) (git-fixes).

  - cxgb3: fix error return code in t3_sge_alloc_qset()
    (git-fixes).

  - cxgb4: fix all-mask IP address comparison (git-fixes).

  - cxgb4: fix checks for max queues to allocate
    (git-fixes).

  - cxgb4: fix endian conversions for L4 ports in filters
    (git-fixes).

  - cxgb4: fix set but unused variable when DCB is disabled
    (git-fixes).

  - cxgb4: fix SGE queue dump destination buffer context
    (git-fixes).

  - cxgb4: fix the panic caused by non smac rewrite
    (git-fixes).

  - cxgb4: move DCB version extern to header file
    (git-fixes).

  - cxgb4: move handling L2T ARP failures to caller
    (git-fixes).

  - cxgb4: move PTP lock and unlock to caller in Tx path
    (git-fixes).

  - cxgb4: parse TC-U32 key values and masks natively
    (git-fixes).

  - cxgb4: remove cast when saving IPv4 partial checksum
    (git-fixes).

  - cxgb4: set up filter action after rewrites (git-fixes).

  - cxgb4: use correct type for all-mask IP address
    comparison (git-fixes).

  - cxgb4: use unaligned conversion for fetching timestamp
    (git-fixes).

  - dmaengine: fsldma: Fix a resource leak in an error
    handling path of the probe function (git-fixes).

  - dmaengine: fsldma: Fix a resource leak in the remove
    function (git-fixes).

  - dmaengine: hsu: disable spurious interrupt (git-fixes).

  - dmaengine: owl-dma: Fix a resource leak in the remove
    function (git-fixes).

  - dm crypt: avoid truncating the logical block size
    (git-fixes).

  - dm: fix bio splitting and its bio completion order for
    regular IO (git-fixes).

  - dm thin: fix use-after-free in
    metadata_pre_commit_callback (bsc#1177529).

  - dm thin metadata: Avoid returning cmd->bm wild pointer
    on error (bsc#1177529).

  - dm thin metadata: fix lockdep complaint (bsc#1177529).

  - dm thin metadata: Fix use-after-free in
    dm_bm_set_read_only (bsc#1177529).

  - dm: use noio when sending kobject event (bsc#1177529).

  - docs: filesystems: vfs: correct flag name (bsc#1182856).

  - dpaa2-eth: fix return codes used in ndo_setup_tc
    (git-fixes).

  - Drivers: hv: vmbus: Avoid use-after-free in
    vmbus_onoffer_rescind() (git-fixes).

  - drivers: net: davinci_mdio: fix potential NULL
    dereference in davinci_mdio_probe() (git-fixes).

  - drivers: soc: atmel: add null entry at the end of
    at91_soc_allowed_list[] (git-fixes).

  - drivers: soc: atmel: Avoid calling at91_soc_init on non
    AT91 SoCs (git-fixes).

  - drm/amd/display: Change function decide_dp_link_settings
    to avoid infinite looping (git-fixes).

  - drm/amd/display: Decrement refcount of dc_sink before
    reassignment (git-fixes).

  - drm/amd/display: Fix 10/12 bpc setup in DCE output bit
    depth reduction (git-fixes).

  - drm/amd/display: Fix dc_sink kref count in
    emulated_link_detect (git-fixes).

  - drm/amd/display: Fix HDMI deep color output for DCE 6-11
    (git-fixes).

  - drm/amd/display: Free atomic state after
    drm_atomic_commit (git-fixes).

  - drm/amd/display: Revert 'Fix EDID parsing after resume
    from suspend' (git-fixes).

  - drm/amdgpu: Fix macro name _AMDGPU_TRACE_H_ in
    preprocessor if condition (git-fixes).

  - drm/fb-helper: Add missed unlocks in setcmap_legacy()
    (git-fixes).

  - drm/gma500: Fix error return code in psb_driver_load()
    (git-fixes).

  - drm/meson: Unbind all connectors on module removal
    (bsc#1152472)

  - drm/sun4i: dw-hdmi: always set clock rate (bsc#1152472)

  - drm/sun4i: dw-hdmi: Fix max. frequency for H6
    (bsc#1152472)

  - drm/sun4i: Fix H6 HDMI PHY configuration (bsc#1152472)

  - drm/sun4i: tcon: set sync polarity for tcon1 channel
    (bsc#1152472)

  - drm/vc4: hvs: Fix buffer overflow with the dlist
    handling (bsc#1152489)

  - exec: Always set cap_ambient in cap_bprm_set_creds
    (git-fixes).

  - exfat: Avoid allocating upcase table using kcalloc()
    (git-fixes).

  - ext4: do not remount read-only with errors=continue on
    reboot (bsc#1182464).

  - ext4: fix a memory leak of ext4_free_data (bsc#1182447).

  - ext4: fix bug for rename with RENAME_WHITEOUT
    (bsc#1182449).

  - ext4: fix deadlock with fs freezing and EA inodes
    (bsc#1182463).

  - ext4: fix superblock checksum failure when setting
    password salt (bsc#1182465).

  - ext4: prevent creating duplicate encrypted filenames
    (bsc#1182446).

  - fgraph: Initialize tracing_graph_pause at task creation
    (git-fixes).

  - firmware_loader: align .builtin_fw to 8 (git-fixes).

  - fscrypt: add fscrypt_is_nokey_name() (bsc#1182446).

  - fscrypt: rename DCACHE_ENCRYPTED_NAME to
    DCACHE_NOKEY_NAME (bsc#1182446).

  - fs: fix lazytime expiration handling in
    __writeback_single_inode() (bsc#1182466).

  - gma500: clean up error handling in init (git-fixes).

  - gpio: pcf857x: Fix missing first interrupt (git-fixes).

  - HID: core: detect and skip invalid inputs to snto32()
    (git-fixes).

  - HID: make arrays usage and value to be the same
    (git-fixes).

  - HID: wacom: Ignore attempts to overwrite the touch_max
    value from HID (git-fixes).

  - hwrng: timeriomem - Fix cooldown period calculation
    (git-fixes).

  - i2c: brcmstb: Fix brcmstd_send_i2c_cmd condition
    (git-fixes).

  - i2c: iproc: handle only slave interrupts which are
    enabled (git-fixes).

  - i2c: mediatek: Move suspend and resume handling to NOIRQ
    phase (git-fixes).

  - i2c: stm32f7: fix configuration of the digital filter
    (git-fixes).

  - i3c: master: dw: Drop redundant disec call (git-fixes).

  - i40e: acquire VSI pointer only after VF is initialized
    (jsc#SLE-8025).

  - i40e: avoid premature Rx buffer reuse (git-fixes).

  - i40e: Fix Error I40E_AQ_RC_EINVAL when removing VFs
    (git-fixes).

  - i40e: Fix MAC address setting for a VF via Host/VM
    (git-fixes).

  - i40e: Fix removing driver while bare-metal VFs pass
    traffic (git-fixes).

  - i40e: Revert 'i40e: do not report link up for a VF who
    hasn't enabled queues' (jsc#SLE-8025).

  - iavf: fix double-release of rtnl_lock (git-fixes).

  - iavf: fix error return code in iavf_init_get_resources()
    (git-fixes).

  - iavf: fix speed reporting over virtchnl (git-fixes).

  - iavf: Fix updating statistics (git-fixes).

  - ibmvnic: add memory barrier to protect long term buffer
    (bsc#1182485 ltc#191591).

  - ibmvnic: change IBMVNIC_MAX_IND_DESCS to 16 (bsc#1182485
    ltc#191591).

  - ibmvnic: Clean up TX code and TX buffer data structure
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: Clear failover_pending if unable to schedule
    (bsc#1181960 ltc#190997).

  - ibmvnic: compare adapter->init_done_rc with more
    readable ibmvnic_rc_codes (jsc#SLE-17043 bsc#1179243
    ltc#189290).

  - ibmvnic: Correctly re-enable interrupts in NAPI polling
    routine (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: create send_control_ip_offload (jsc#SLE-17043
    bsc#1179243 ltc#189290).

  - ibmvnic: create send_query_ip_offload (jsc#SLE-17043
    bsc#1179243 ltc#189290).

  - ibmvnic: device remove has higher precedence over reset
    (bsc#1065729).

  - ibmvnic: Do not replenish RX buffers after every polling
    loop (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: Ensure that CRQ entry read are correctly
    ordered (bsc#1182485 ltc#191591).

  - ibmvnic: Ensure that device queue memory is cache-line
    aligned (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: Ensure that SCRQ entry reads are correctly
    ordered (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: fix a race between open and reset (bsc#1176855
    ltc#187293).

  - ibmvnic: fix login buffer memory leak (bsc#1081134
    ltc#164631).

  - ibmvnic: fix NULL pointer dereference in
    ibmvic_reset_crq (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: fix rx buffer tracking and index management in
    replenish_rx_pool partial success (bsc#1179929
    ltc#189960).

  - ibmvnic: Fix TX completion error handling (jsc#SLE-17043
    bsc#1179243 ltc#189290).

  - ibmvnic: Fix use-after-free of VNIC login response
    buffer (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: handle inconsistent login with reset
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: Harden device Command Response Queue handshake
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: improve ibmvnic_init and ibmvnic_reset_init
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: Introduce batched RX buffer descriptor
    transmission (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: Introduce indirect subordinate Command Response
    Queue buffer (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: Introduce xmit_more support using batched
    subCRQ hcalls (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: merge ibmvnic_reset_init and ibmvnic_init
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: no reset timeout for 5 seconds after reset
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: reduce wait for completion time (jsc#SLE-17043
    bsc#1179243 ltc#189290).

  - ibmvnic: remove never executed if statement
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: Remove send_subcrq function (jsc#SLE-17043
    bsc#1179243 ltc#189290).

  - ibmvnic: rename ibmvnic_send_req_caps to
    send_request_cap (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: rename send_cap_queries to send_query_cap
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: rename send_map_query to send_query_map
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: send_login should check for crq errors
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: serialize access to work queue on remove
    (bsc#1065729).

  - ibmvnic: Set to CLOSED state even on error (bsc#1084610
    ltc#165122 git-fixes).

  - ibmvnic: skip send_request_unmap for timeout reset
    (bsc#1182485 ltc#191591).

  - ibmvnic: skip tx timeout reset while in resetting
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: stop free_all_rwi on failed reset
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - ibmvnic: store RX and TX subCRQ handle array in
    ibmvnic_adapter struct (jsc#SLE-17043 bsc#1179243
    ltc#189290).

  - ibmvnic: track pending login (jsc#SLE-17043 bsc#1179243
    ltc#189290).

  - ibmvnic: update MAINTAINERS (jsc#SLE-17043 bsc#1179243
    ltc#189290).

  - ibmvnic: Use netdev_alloc_skb instead of alloc_skb to
    replenish RX buffers (jsc#SLE-17043 bsc#1179243
    ltc#189290).

  - ice: Do not allow more channels than LAN MSI-X available
    (jsc#SLE-7926).

  - ice: Fix MSI-X vector fallback logic (jsc#SLE-7926).

  - igc: check return value of ret_val in
    igc_config_fc_after_link_up (git-fixes).

  - igc: fix link speed advertising (git-fixes).

  - igc: Fix returning wrong statistics (git-fixes).

  - igc: Report speed and duplex as unknown when device is
    runtime suspended (git-fixes).

  - igc: set the default return value to -IGC_ERR_NVM in
    igc_write_nvm_srwr (git-fixes).

  - include/linux/memremap.h: remove stale comments
    (git-fixes).

  - Input: elo - fix an error code in elo_connect()
    (git-fixes).

  - Input: i8042 - unbreak Pegatron C15B (git-fixes).

  - Input: joydev - prevent potential read overflow in ioctl
    (git-fixes).

  - Input: sur40 - fix an error code in sur40_probe()
    (git-fixes).

  - Input: xpad - sync supported devices with fork on GitHub
    (git-fixes).

  - iwlwifi: mvm: do not send RFH_QUEUE_CONFIG_CMD with no
    queues (git-fixes).

  - iwlwifi: mvm: guard against device removal in reprobe
    (git-fixes).

  - iwlwifi: mvm: invalidate IDs of internal stations at mvm
    start (git-fixes).

  - iwlwifi: mvm: skip power command when unbinding vif
    during CSA (git-fixes).

  - iwlwifi: mvm: take mutex for calling
    iwl_mvm_get_sync_time() (git-fixes).

  - iwlwifi: pcie: add a NULL check in iwl_pcie_txq_unmap
    (git-fixes).

  - iwlwifi: pcie: fix context info memory leak (git-fixes).

  - iwlwifi: pcie: reschedule in long-running memory reads
    (git-fixes).

  - iwlwifi: pcie: use jiffies for memory read spin time
    limit (git-fixes).

  - ixgbe: avoid premature Rx buffer reuse (git-fixes).

  - ixgbe: Fix XDP redirect on archs with PAGE_SIZE above 4K
    (git-fixes).

  - kABI: Fix kABI after AMD SEV PCID fixes (bsc#1178995).

  - kABI: Fix kABI after modifying struct __call_single_data
    (bsc#1180846).

  - kABI: Fix kABI for extended APIC-ID support
    (bsc#1181259, jsc#ECO-3191).

  - kABI: repair, after 'nVMX: Emulate MTF when
    performinginstruction emulation' kvm_x86_ops is part of
    kABI as it's used by LTTng. But it's only read and never
    allocated in there, so growing it (without altering
    existing members' offsets) is fine.

  - kernel-binary.spec: Add back initrd and image symlink
    ghosts to filelist (bsc#1182140). Fixes: 76a9256314c3
    ('rpm/kernel-(source,binary).spec: do not include ghost
    symlinks (boo#1179082).')

  - kernel/smp: add boot parameter for controlling CSD lock
    debugging (bsc#1180846).

  - kernel/smp: add more data to CSD lock debugging
    (bsc#1180846).

  - kernel/smp: prepare more CSD lock debugging
    (bsc#1180846).

  - kernel/smp: Provide CSD lock timeout diagnostics
    (bsc#1180846).

  - KVM: arm64: Assume write fault on S1PTW permission fault
    on instruction fetch (bsc#1181818).

  - KVM: arm64: Remove S1PTW check from
    kvm_vcpu_dabt_iswrite() (bsc#1181818).

  - KVM: nVMX: do not clear mtf_pending when nested events
    are blocked (bsc#1182489).

  - KVM: nVMX: Emulate MTF when performing instruction
    emulation (bsc#1182380).

  - KVM: nVMX: Handle pending #DB when injecting INIT
    VM-exit. Pulling in as a dependency of: 'KVM: nVMX:
    Emulate MTF when performing instruction emulation'
    (bsc#1182380).

  - KVM: SVM: Update cr3_lm_rsvd_bits for AMD SEV guests
    (bsc#1178995).

  - KVM: tracing: Fix unmatched kvm_entry and kvm_exit
    events (bsc#1182770).

  - KVM: VMX: Condition ENCLS-exiting enabling on CPU
    support for SGX1 (bsc#1182798).

  - KVM: x86: Allocate new rmap and large page tracking when
    moving memslot (bsc#1182800).

  - KVM: x86: allow KVM_STATE_NESTED_MTF_PENDING in
    kvm_state flags (bsc#1182490).

  - KVM: x86: clear stale x86_emulate_ctxt->intercept value
    (bsc#1182381).

  - KVM: x86: do not notify userspace IOAPIC on
    edge-triggered interrupt EOI (bsc#1182374).

  - KVM: x86: Gracefully handle __vmalloc() failure during
    VM allocation (bsc#1182801).

  - KVM: x86: Introduce cr3_lm_rsvd_bits in kvm_vcpu_arch
    (bsc#1178995).

  - KVM: x86: remove stale comment from struct
    x86_emulate_ctxt (bsc#1182406).

  - libnvdimm/dimm: Avoid race between probe and
    available_slots_show() (bsc#1170442).

  - lib/vsprintf: no_hash_pointers prints all addresses as
    unhashed (bsc#1182599).

  - linux/clk.h: use correct kernel-doc notation for 2
    functions (git-fixes).

  - mac80211: 160MHz with extended NSS BW in CSA
    (git-fixes).

  - mac80211: fix fast-rx encryption check (git-fixes).

  - mac80211: fix potential overflow when multiplying to u32
    integers (git-fixes).

  - mac80211: pause TX while changing interface type
    (git-fixes).

  - macros.kernel-source: Use spec_install_pre for
    certificate installation (boo#1182672). Since rpm 4.16
    files installed during build phase are lost.

  - MAINTAINERS: remove John Allen from ibmvnic
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - matroxfb: avoid -Warray-bounds warning (bsc#1152472)

  - media: aspeed: fix error return code in
    aspeed_video_setup_video() (git-fixes).

  - media: camss: missing error code in msm_video_register()
    (git-fixes).

  - media: cx25821: Fix a bug when reallocating some dma
    memory (git-fixes).

  - media: em28xx: Fix use-after-free in em28xx_alloc_urbs
    (git-fixes).

  - media: i2c: ov5670: Fix PIXEL_RATE minimum value
    (git-fixes).

  - media: ipu3-cio2: Fix mbus_code processing in
    cio2_subdev_set_fmt() (git-fixes).

  - media: lmedm04: Fix misuse of comma (git-fixes).

  - media: media/pci: Fix memleak in empress_init
    (git-fixes).

  - media: mt9v111: Remove unneeded device-managed puts
    (git-fixes).

  - media: pwc: Use correct device for DMA (bsc#1181133).

  - media: pxa_camera: declare variable when DEBUG is
    defined (git-fixes).

  - media: qm1d1c0042: fix error return code in
    qm1d1c0042_init() (git-fixes).

  - media: software_node: Fix refcounts in
    software_node_get_next_child() (git-fixes).

  - media: tm6000: Fix memleak in tm6000_start_stream
    (git-fixes).

  - media: vsp1: Fix an error handling path in the probe
    function (git-fixes).

  - mei: hbm: call mei_set_devstate() on hbm stop response
    (git-fixes).

  - memory: ti-aemif: Drop child node when jumping out loop
    (git-fixes).

  - mfd: bd9571mwv: Use devm_mfd_add_devices() (git-fixes).

  - mfd: wm831x-auxadc: Prevent use after free in
    wm831x_auxadc_read_irq() (git-fixes).

  - misc: eeprom_93xx46: Add module alias to avoid breaking
    support for non device tree users (git-fixes).

  - misc: eeprom_93xx46: Fix module alias to enable module
    autoprobe (git-fixes).

  - mlxsw: core: Add validation of transceiver temperature
    thresholds (git-fixes).

  - mlxsw: core: Fix memory leak on module removal
    (git-fixes).

  - mlxsw: core: Fix use-after-free in
    mlxsw_emad_trans_finish() (git-fixes).

  - mlxsw: core: Free EMAD transactions using kfree_rcu()
    (git-fixes).

  - mlxsw: core: Increase critical threshold for ASIC
    thermal zone (git-fixes).

  - mlxsw: core: Increase scope of RCU read-side critical
    section (git-fixes).

  - mlxsw: core: Use variable timeout for EMAD retries
    (git-fixes).

  - mlxsw: spectrum_acl: Fix mlxsw_sp_acl_tcam_group_add()'s
    error path (git-fixes).

  - mlxsw: spectrum: Fix use-after-free of
    split/unsplit/type_set in case reload fails (git-fixes).

  - mmc: core: Limit retries when analyse of SDIO tuples
    fails (git-fixes).

  - mmc: renesas_sdhi_internal_dmac: Fix DMA buffer
    alignment from 8 to 128-bytes (git-fixes).

  - mmc: sdhci-sprd: Fix some resource leaks in the remove
    function (git-fixes).

  - mmc: usdhi6rol0: Fix a resource leak in the error
    handling path of the probe (git-fixes).

  - mm/pmem: avoid inserting hugepage PTE entry with fsdax
    if hugepage support is disabled (bsc#1181896
    ltc#191273).

  - mm: proc: Invalidate TLB after clearing soft-dirty page
    state (bsc#1163776 ltc#183929 git-fixes).

  - mm: thp: kABI: move the added flag to the end of enum
    (bsc#1181896 ltc#191273).

  - mt76: dma: fix a possible memory leak in
    mt76_add_fragment() (git-fixes).

  - net: ag71xx: add missed clk_disable_unprepare in error
    path of probe (git-fixes).

  - net: axienet: Fix error return code in axienet_probe()
    (git-fixes).

  - net: bcmgenet: Fix WoL with password after deep sleep
    (git-fixes).

  - net: bcmgenet: keep MAC in reset until PHY is up
    (git-fixes).

  - net: bcmgenet: re-remove bcmgenet_hfb_add_filter
    (git-fixes).

  - net: bcmgenet: set Rx mode before starting netif
    (git-fixes).

  - net: bcmgenet: use hardware padding of runt frames
    (git-fixes).

  - net: broadcom CNIC: requires MMU (git-fixes).

  - net: caif: Fix debugfs on 64-bit platforms (git-fixes).

  - net/cxgb4: Check the return from t4_query_params
    properly (git-fixes).

  - net: cxgb4: fix return error value in t4_prep_fw
    (git-fixes).

  - net: dsa: bcm_sf2: Fix overflow checks (git-fixes).

  - net: dsa: lantiq_gswip: fix and improve the unsupported
    interface error (git-fixes).

  - net: dsa: mt7530: Change the LINK bit to reflect the
    link status (git-fixes).

  - net: dsa: mt7530: set CPU port to fallback mode
    (git-fixes).

  - net: ena: set initial DMA width to avoid intel iommu
    issue (git-fixes).

  - net: ethernet: ave: Fix error returns in ave_init
    (git-fixes).

  - net: ethernet: mlx4: Avoid assigning a value to
    ring_cons but not used it anymore in mlx4_en_xmit()
    (git-fixes).

  - net: ethernet: ti: ale: fix allmulti for nu type ale
    (git-fixes).

  - net: ethernet: ti: ale: fix seeing unreg mcast packets
    with promisc and allmulti disabled (git-fixes).

  - net: ethernet: ti: ale: modify vlan/mdb api for
    switchdev (git-fixes).

  - net: ethernet: ti: cpsw: allow untagged traffic on host
    port (git-fixes).

  - net: ethernet: ti: fix some return value check of
    cpsw_ale_create() (git-fixes).

  - net: gemini: Fix missing clk_disable_unprepare() in
    error path of gemini_ethernet_port_probe() (git-fixes).

  - net: gro: do not keep too many GRO packets in
    napi->rx_list (bsc#1154353).

  - net: hns3: add a check for queue_id in
    hclge_reset_vf_queue() (git-fixes).

  - net: hns3: add a missing uninit debugfs when unload
    driver (git-fixes).

  - net: hns3: add reset check for VF updating port based
    VLAN (git-fixes).

  - net: hns3: clear port base VLAN when unload PF
    (git-fixes).

  - net: hns3: fix aRFS FD rules leftover after add a user
    FD rule (git-fixes).

  - net: hns3: fix a TX timeout issue (git-fixes).

  - net: hns3: fix desc filling bug when skb is expanded or
    lineared (git-fixes).

  - net: hns3: fix for mishandle of asserting VF reset fail
    (git-fixes).

  - net: hns3: fix for VLAN config when reset failed
    (git-fixes).

  - net: hns3: fix RSS config lost after VF reset
    (git-fixes).

  - net: hns3: fix set and get link ksettings issue
    (git-fixes).

  - net: hns3: fix 'tc qdisc del' failed issue (git-fixes).

  - net: hns3: fix the number of queues actually used by ARQ
    (git-fixes).

  - net: hns3: fix use-after-free when doing self test
    (git-fixes).

  - net: hns3: fix VF VLAN table entries inconsistent issue
    (git-fixes).

  - net: hns: fix return value check in __lb_other_process()
    (git-fixes).

  - net: lpc-enet: fix error return code in lpc_mii_init()
    (git-fixes).

  - net: macb: fix call to pm_runtime in the suspend/resume
    functions (git-fixes).

  - net: macb: fix wakeup test in runtime suspend/resume
    routines (git-fixes).

  - net: macb: mark device wake capable when 'magic-packet'
    property present (git-fixes).

  - net/mlx4_core: fix a memory leak bug (git-fixes).

  - net/mlx4_core: Fix init_hca fields offset (git-fixes).

  - net/mlx4_en: Avoid scheduling restart task if it is
    already running (bsc#1181854).

  - net/mlx4_en: Handle TX error CQE (bsc#1181854).

  - net/mlx5: Add handling of port type in rule deletion
    (git-fixes).

  - net/mlx5: Annotate mutex destroy for root ns
    (git-fixes).

  - net/mlx5: Clear LAG notifier pointer after unregister
    (git-fixes).

  - net/mlx5: Disable QoS when min_rates on all VFs are zero
    (git-fixes).

  - net/mlx5: Do not call timecounter cyc2time directly from
    1PPS flow (git-fixes).

  - net/mlx5: Do not maintain a case of del_sw_func being
    null (git-fixes).

  - net/mlx5e: Correctly handle changing the number of
    queues when the interface is down (git-fixes).

  - net/mlx5e: Do not trigger IRQ multiple times on XSK
    wakeup to avoid WQ overruns (git-fixes).

  - net/mlx5e: en_accel, Add missing net/geneve.h include
    (git-fixes).

  - net/mlx5e: Encapsulate updating netdev queues into a
    function (git-fixes).

  - net/mlx5e: E-switch, Fix rate calculation for overflow
    (jsc#SLE-8464).

  - net/mlx5e: fix bpf_prog reference count leaks in
    mlx5e_alloc_rq (git-fixes).

  - net/mlx5e: Fix configuration of XPS cpumasks and netdev
    queues in corner cases (git-fixes).

  - net/mlx5e: Fix endianness handling in pedit mask
    (git-fixes).

  - net/mlx5e: Fix error path of device attach (git-fixes).

  - net/mlx5e: Fix memleak in mlx5e_create_l2_table_groups
    (git-fixes).

  - net/mlx5e: Fix two double free cases (git-fixes).

  - net/mlx5e: Fix VLAN cleanup flow (git-fixes).

  - net/mlx5e: Fix VLAN create flow (git-fixes).

  - net/mlx5e: Get the latest values from counters in
    switchdev mode (git-fixes).

  - net/mlx5e: IPoIB, Drop multicast packets that this
    interface sent (git-fixes).

  - net/mlx5e: kTLS, Fix wrong value in record tracker enum
    (git-fixes).

  - net/mlx5e: Reduce tc unsupported key print level
    (git-fixes).

  - net/mlx5e: Rename hw_modify to preactivate (git-fixes).

  - net/mlx5e: Set of completion request bit should not
    clear other adjacent bits (git-fixes).

  - net/mlx5: E-switch, Destroy TSAR after reload interface
    (git-fixes).

  - net/mlx5: E-Switch, Hold mutex when querying drop
    counter in legacy mode (git-fixes).

  - net/mlx5: E-Switch, Use vport metadata matching by
    default (git-fixes).

  - net/mlx5: E-Switch, Use vport metadata matching only
    when mandatory (git-fixes).

  - net/mlx5e: Use preactivate hook to set the indirection
    table (git-fixes).

  - net/mlx5e: vxlan: Use RCU for vxlan table lookup
    (git-fixes).

  - net/mlx5: Fix a bug of using ptp channel index as pin
    index (git-fixes).

  - net/mlx5: Fix deletion of duplicate rules (git-fixes).

  - net/mlx5: Fix failing fw tracer allocation on s390
    (git-fixes).

  - net/mlx5: Fix memory leak on flow table creation error
    flow (git-fixes).

  - net/mlx5: Fix request_irqs error flow (git-fixes).

  - net/mlx5: Fix wrong address reclaim when command
    interface is down (git-fixes).

  - net/mlx5: Query PPS pin operational status before
    registering it (git-fixes).

  - net/mlx5: Verify Hardware supports requested ptp
    function on a given pin (git-fixes).

  - net: moxa: Fix a potential double 'free_irq()'
    (git-fixes).

  - net: mscc: ocelot: ANA_AUTOAGE_AGE_PERIOD holds a value
    in seconds, not ms (git-fixes).

  - net: mscc: ocelot: fix address ageing time (again)
    (git-fixes).

  - net: mscc: ocelot: properly account for VLAN header
    length when setting MRU (git-fixes).

  - net: mvpp2: Add TCAM entry to drop flow control pause
    frames (git-fixes).

  - net: mvpp2: disable force link UP during port init
    procedure (git-fixes).

  - net: mvpp2: Fix error return code in mvpp2_open()
    (git-fixes).

  - net: mvpp2: Fix GoP port 3 Networking Complex Control
    configurations (git-fixes).

  - net: mvpp2: fix memory leak in mvpp2_rx (git-fixes).

  - net: mvpp2: fix pkt coalescing int-threshold
    configuration (git-fixes).

  - net: mvpp2: prs: fix PPPoE with ipv6 packet parse
    (git-fixes).

  - net: mvpp2: Remove Pause and Asym_Pause support
    (git-fixes).

  - net: mvpp2: TCAM entry enable should be written after
    SRAM data (git-fixes).

  - net: netsec: Correct dma sync for XDP_TX frames
    (git-fixes).

  - net: nixge: fix potential memory leak in nixge_probe()
    (git-fixes).

  - net: octeon: mgmt: Repair filling of RX ring
    (git-fixes).

  - net: phy: at803x: use operating parameters from
    PHY-specific status (git-fixes).

  - net: phy: extract link partner advertisement reading
    (git-fixes).

  - net: phy: extract pause mode (git-fixes).

  - net: phy: marvell10g: fix NULL pointer dereference
    (git-fixes).

  - net: phy: marvell10g: fix temperature sensor on 2110
    (git-fixes).

  - net: phy: read MII_CTRL1000 in genphy_read_status only
    if needed (git-fixes).

  - net: qca_spi: fix receive buffer size check (git-fixes).

  - net: qca_spi: Move reset_count to struct qcaspi
    (git-fixes).

  - net: qede: fix PTP initialization on recovery
    (git-fixes).

  - net: qede: fix use-after-free on recovery and AER
    handling (git-fixes).

  - net: qede: stop adding events on an already destroyed
    workqueue (git-fixes).

  - net: qed: fix async event callbacks unregistering
    (git-fixes).

  - net: qed: fix excessive QM ILT lines consumption
    (git-fixes).

  - net: qed: fix 'maybe uninitialized' warning (git-fixes).

  - net: qed: fix NVMe login fails over VFs (git-fixes).

  - net: qed: RDMA personality shouldn't fail VF load
    (git-fixes).

  - net: re-solve some conflicts after net -> net-next merge
    (bsc#1176855 ltc#187293).

  - net: rmnet: do not allow to add multiple bridge
    interfaces (git-fixes).

  - net: rmnet: do not allow to change mux id if mux id is
    duplicated (git-fixes).

  - net: rmnet: fix bridge mode bugs (git-fixes).

  - net: rmnet: fix lower interface leak (git-fixes).

  - net: rmnet: fix NULL pointer dereference in
    rmnet_changelink() (git-fixes).

  - net: rmnet: fix NULL pointer dereference in
    rmnet_newlink() (git-fixes).

  - net: rmnet: fix packet forwarding in rmnet bridge mode
    (git-fixes).

  - net: rmnet: fix suspicious RCU usage (git-fixes).

  - net: rmnet: print error message when command fails
    (git-fixes).

  - net: rmnet: remove rcu_read_lock in
    rmnet_force_unassociate_device() (git-fixes).

  - net: rmnet: use upper/lower device infrastructure
    (git-fixes).

  - net, sctp, filter: remap copy_from_user failure error
    (bsc#1181637).

  - net: smc91x: Fix possible memory leak in smc_drv_probe()
    (git-fixes).

  - net/sonic: Add mutual exclusion for accessing shared
    state (git-fixes).

  - net: stmmac: 16KB buffer must be 16 byte aligned
    (git-fixes).

  - net: stmmac: Always arm TX Timer at end of transmission
    start (git-fixes).

  - net: stmmac: Do not accept invalid MTU values
    (git-fixes).

  - net: stmmac: dwmac-sunxi: Provide TX and RX fifo sizes
    (git-fixes).

  - net: stmmac: Enable 16KB buffer size (git-fixes).

  - net: stmmac: fix disabling flexible PPS output
    (git-fixes).

  - net: stmmac: fix length of PTP clock's name string
    (git-fixes).

  - net: stmmac: Fix the TX IOC in xmit path (git-fixes).

  - net: stmmac: RX buffer size must be 16 byte aligned
    (git-fixes).

  - net: stmmac: selftests: Flow Control test can also run
    with ASYM Pause (git-fixes).

  - net: stmmac: selftests: Needs to check the number of
    Multicast regs (git-fixes).

  - net: stmmac: xgmac: Clear previous RX buffer size
    (git-fixes).

  - net: sun: fix missing release regions in cas_init_one()
    (git-fixes).

  - net: team: fix memory leak in __team_options_register
    (git-fixes).

  - net: thunderx: initialize VF's mailbox mutex before
    first usage (git-fixes).

  - net: usb: qmi_wwan: added support for Thales Cinterion
    PLSx3 modem family (git-fixes).

  - net: usb: qmi_wwan: Adding support for Cinterion MV31
    (git-fixes).

  - nvme-hwmon: rework to avoid devm allocation
    (bsc#1177326).

  - nvme-multipath: Early exit if no path is available
    (bsc#1180964).

  - nvme: re-read ANA log on NS CHANGED AEN (bsc#1179137).

  - nvmet-tcp: Fix NULL dereference when a connect data
    comes in h2cdata pdu (bsc#1182547).

  - objtool: Do not fail on missing symbol table
    (bsc#1169514).

  - perf/x86/intel/uncore: Factor out
    uncore_pci_find_dev_pmu() (bsc#1180989).

  - perf/x86/intel/uncore: Factor out
    uncore_pci_get_dev_die_info() (bsc#1180989).

  - perf/x86/intel/uncore: Factor out
    uncore_pci_pmu_register() (bsc#1180989).

  - perf/x86/intel/uncore: Factor out
    uncore_pci_pmu_unregister() (bsc#1180989).

  - perf/x86/intel/uncore: Generic support for the PCI sub
    driver (bsc#1180989).

  - perf/x86/intel/uncore: Store the logical die id instead
    of the physical die id (bsc#1180989).

  - perf/x86/intel/uncore: With > 8 nodes, get pci bus die
    id from NUMA info (bsc#1180989).

  - phy: cpcap-usb: Fix warning for missing
    regulator_disable (git-fixes).

  - phy: rockchip-emmc: emmc_phy_init() always return 0
    (git-fixes).

  - platform/x86: hp-wmi: Disable tablet-mode reporting by
    default (git-fixes).

  - platform/x86: intel-vbtn: Support for tablet mode on
    Dell Inspiron 7352 (git-fixes).

  - platform/x86: touchscreen_dmi: Add swap-x-y quirk for
    Goodix touchscreen on Estar Beauty HD tablet
    (git-fixes).

  - powerpc/book3s64/hash: Add cond_resched to avoid soft
    lockup warning (bsc#1182571 ltc#191345).

  - powerpc/boot: Delete unneeded .globl _zimage_start
    (bsc#1156395).

  - powerpc: Fix alignment bug within the init sections
    (bsc#1065729).

  - powerpc/fpu: Drop cvt_fd() and cvt_df() (bsc#1156395).

  - powerpc/hvcall: add token and codes for H_VASI_SIGNAL
    (bsc#1181674 ltc#189159).

  - powerpc: kABI: add back suspend_disable_cpu in
    machdep_calls (bsc#1181674 ltc#189159).

  - powerpc/machdep: remove suspend_disable_cpu()
    (bsc#1181674 ltc#189159).

  - powerpc/mm/pkeys: Make pkey access check work on
    execute_only_key (bsc#1181544 ltc#191080 git-fixes).

  - powerpc/numa: Fix build when CONFIG_NUMA=n (bsc#1132477
    ltc#175530).

  - powerpc/numa: make vphn_enabled, prrn_enabled flags
    const (bsc#1181674 ltc#189159).

  - powerpc/numa: remove ability to enable topology updates
    (bsc#1181674 ltc#189159).

  - powerpc/numa: remove arch_update_cpu_topology
    (bsc#1181674 ltc#189159).

  - powerpc/numa: Remove late request for home node
    associativity (bsc#1181674 ltc#189159).

  - powerpc/numa: remove prrn_is_enabled() (bsc#1181674
    ltc#189159).

  - powerpc/numa: remove start/stop_topology_update()
    (bsc#1181674 ltc#189159).

  - powerpc/numa: remove timed_topology_update()
    (bsc#1181674 ltc#189159).

  - powerpc/numa: remove unreachable topology timer code
    (bsc#1181674 ltc#189159).

  - powerpc/numa: remove unreachable topology update code
    (bsc#1181674 ltc#189159).

  - powerpc/numa: remove unreachable topology workqueue code
    (bsc#1181674 ltc#189159).

  - powerpc/numa: remove vphn_enabled and prrn_enabled
    internal flags (bsc#1181674 ltc#189159).

  - powerpc/numa: stub out numa_update_cpu_topology()
    (bsc#1181674 ltc#189159).

  - powerpc/perf: Exclude kernel samples while counting
    events in user space (bsc#1065729).

  - powerpc/perf/hv-24x7: Dont create sysfs event files for
    dummy events (bsc#1182118 ltc#190624).

  - powerpc/pkeys: Avoid using lockless page table walk
    (bsc#1181544 ltc#191080).

  - powerpc/pkeys: Check vma before returning key fault
    error to the user (bsc#1181544 ltc#191080).

  - powerpc/powernv/memtrace: Do not leak kernel memory to
    user space (bsc#1156395).

  - powerpc/powernv/memtrace: Fix crashing the kernel when
    enabling concurrently (bsc#1156395).

  - powerpc/powernv/npu: Do not attempt NPU2 setup on
    POWER8NVL NPU (bsc#1156395).

  - powerpc/prom: Fix 'ibm,arch-vec-5-platform-support' scan
    (bsc#1182602 ltc#190924).

  - powerpc/pseries/dlpar: handle ibm, configure-connector
    delay status (bsc#1181985 ltc#188074).

  - powerpc/pseries: Do not enforce MSI affinity with kdump
    (bsc#1181655 ltc#190855).

  - powerpc/pseries/eeh: Make
    pseries_pcibios_bus_add_device() static (bsc#1078720,
    git-fixes).

  - powerpc/pseries: extract host bridge from pci_bus prior
    to bus removal (bsc#1182171 ltc#190900).

  - powerpc/pseries/hibernation: drop
    pseries_suspend_begin() from suspend ops (bsc#1181674
    ltc#189159).

  - powerpc/pseries/hibernation: pass stream id via function
    arguments (bsc#1181674 ltc#189159).

  - powerpc/pseries/hibernation: perform post-suspend fixups
    later (bsc#1181674 ltc#189159).

  - powerpc/pseries/hibernation: remove prepare_late()
    callback (bsc#1181674 ltc#189159).

  - powerpc/pseries/hibernation: remove
    pseries_suspend_cpu() (bsc#1181674 ltc#189159).

  - powerpc/pseries/hibernation: switch to
    rtas_ibm_suspend_me() (bsc#1181674 ltc#189159).

  - powerpc/pseries/mobility: add missing break to default
    case (bsc#1181674 ltc#189159).

  - powerpc/pseries/mobility: Add pr_debug() for device tree
    changes (bsc#1181674 ltc#189159).

  - powerpc/pseries/mobility: do not error on absence of
    ibm, update-nodes (bsc#1181674 ltc#189159).

  - powerpc/pseries/mobility: error message improvements
    (bsc#1181674 ltc#189159).

  - powerpc/pseries/mobility: extract VASI session polling
    logic (bsc#1181674 ltc#189159).

  - powerpc/pseries/mobility: refactor node lookup during DT
    update (bsc#1181674 ltc#189159).

  - powerpc/pseries/mobility: retry partition suspend after
    error (bsc#1181674 ltc#189159).

  - powerpc/pseries/mobility: Set pr_fmt() (bsc#1181674
    ltc#189159).

  - powerpc/pseries/mobility: signal suspend cancellation to
    platform (bsc#1181674 ltc#189159).

  - powerpc/pseries/mobility: use rtas_activate_firmware()
    on resume (bsc#1181674 ltc#189159).

  - powerpc/pseries/mobility: use stop_machine for
    join/suspend (bsc#1181674 ltc#189159).

  - powerpc/pseries/ras: Make init_ras_hotplug_IRQ() static
    (bsc#1065729. git-fixes).

  - powerpc/pseries: remove dlpar_cpu_readd() (bsc#1181674
    ltc#189159).

  - powerpc/pseries: remove memory 're-add' implementation
    (bsc#1181674 ltc#189159).

  - powerpc/pseries: remove obsolete memory hotplug DT
    notifier code (bsc#1181674 ltc#189159).

  - powerpc/pseries: remove prrn special case from DT update
    path (bsc#1181674 ltc#189159).

  - powerpc/rtas: add rtas_activate_firmware() (bsc#1181674
    ltc#189159).

  - powerpc/rtas: add rtas_ibm_suspend_me() (bsc#1181674
    ltc#189159).

  - powerpc/rtas: complete ibm,suspend-me status codes
    (bsc#1181674 ltc#189159).

  - powerpc/rtas: dispatch partition migration requests to
    pseries (bsc#1181674 ltc#189159).

  - powerpc/rtasd: simplify handle_rtas_event(), emit
    message on events (bsc#1181674 ltc#189159).

  - powerpc/rtas: prevent suspend-related sys_rtas use on LE
    (bsc#1181674 ltc#189159).

  - powerpc/rtas: remove rtas_ibm_suspend_me_unsafe()
    (bsc#1181674 ltc#189159).

  - powerpc/rtas: remove rtas_suspend_cpu() (bsc#1181674
    ltc#189159).

  - powerpc/rtas: remove unused rtas_suspend_last_cpu()
    (bsc#1181674 ltc#189159).

  - powerpc/rtas: remove unused rtas_suspend_me_data
    (bsc#1181674 ltc#189159).

  - powerpc/rtas: rtas_ibm_suspend_me ->
    rtas_ibm_suspend_me_unsafe (bsc#1181674 ltc#189159).

  - power: reset: at91-sama5d2_shdwc: fix wkupdbc mask
    (git-fixes).

  - pseries/drmem: do not cache node id in drmem_lmb struct
    (bsc#1132477 ltc#175530).

  - pseries/hotplug-memory: hot-add: skip redundant LMB
    lookup (bsc#1132477 ltc#175530).

  - qed: fix error return code in qed_iwarp_ll2_start()
    (git-fixes).

  - qed: Fix race condition between scheduling and
    destroying the slowpath workqueue (git-fixes).

  - qed: Populate nvm-file attributes while reading nvm
    config partition (git-fixes).

  - qed: select CONFIG_CRC32 (git-fixes).

  - qlcnic: fix missing release in
    qlcnic_83xx_interrupt_test (git-fixes).

  - quota: Fix memory leak when handling corrupted quota
    file (bsc#1182650).

  - quota: Sanity-check quota file headers on load
    (bsc#1182461).

  - r8169: fix resuming from suspend on RTL8105e if machine
    runs on battery (git-fixes).

  - r8169: fix WoL on shutdown if CONFIG_DEBUG_SHIRQ is set
    (git-fixes).

  - rcu/nocb: Perform deferred wake up before last idle's
    (git-fixes)

  - rcu/nocb: Trigger self-IPI on late deferred wake up
    before (git-fixes)

  - rcu: Pull deferred rcuog wake up to rcu_eqs_enter()
    callers (git-fixes)

  - RDMA/efa: Add EFA 0xefa1 PCI ID (bsc#1176248).

  - RDMA/efa: Count admin commands errors (bsc#1176248).

  - RDMA/efa: Count mmap failures (bsc#1176248).

  - RDMA/efa: Do not delay freeing of DMA pages
    (bsc#1176248).

  - RDMA/efa: Drop double zeroing for sg_init_table()
    (bsc#1176248).

  - RDMA/efa: Expose maximum TX doorbell batch
    (bsc#1176248).

  - RDMA/efa: Expose minimum SQ size (bsc#1176248).

  - RDMA/efa: Fix setting of wrong bit in get/set_feature
    commands (bsc#1176248).

  - RDMA/efa: Properly document the interrupt mask register
    (bsc#1176248).

  - RDMA/efa: Remove redundant udata check from alloc
    ucontext response (bsc#1176248).

  - RDMA/efa: Report create CQ error counter (bsc#1176248).

  - RDMA/efa: Report host information to the device
    (bsc#1176248).

  - RDMA/efa: Unified getters/setters for device structs
    bitmask access (bsc#1176248).

  - RDMA/efa: Use in-kernel offsetofend() to check field
    availability (bsc#1176248).

  - RDMA/efa: User/kernel compatibility handshake mechanism
    (bsc#1176248).

  - RDMA/efa: Use the correct current and new states in
    modify QP (git-fixes).

  - regulator: axp20x: Fix reference cout leak (git-fixes).

  - regulator: core: Avoid debugfs: Directory ... already
    present! error (git-fixes).

  - regulator: core: avoid regulator_resolve_supply() race
    condition (git-fixes).

  - regulator: Fix lockdep warning resolving supplies
    (git-fixes).

  - regulator: s5m8767: Drop regulators OF node reference
    (git-fixes).

  - regulator: s5m8767: Fix reference count leak
    (git-fixes).

  - reiserfs: add check for an invalid ih_entry_count
    (bsc#1182462).

  - Remove debug patch for boot failure (bsc#1182602
    ltc#190924). 

  - reset: hisilicon: correct vendor prefix (git-fixes).

  - Revert 'ibmvnic: remove never executed if statement'
    (jsc#SLE-17043 bsc#1179243 ltc#189290).

  - Revert 'net: bcmgenet: remove unused function in
    bcmgenet.c' (git-fixes).

  - Revert 'platform/x86: ideapad-laptop: Switch touchpad
    attribute to be RO' (git-fixes).

  - Revert 'RDMA/mlx5: Fix devlink deadlock on net namespace
    deletion' (jsc#SLE-8464).

  - rpm/kernel-subpackage-build: Workaround broken bot
    (https://github.com/openSUSE/openSUSE-release-tools/issu
    es/2439)

  - rpm/post.sh: Avoid purge-kernel for the first installed
    kernel (bsc#1180058)

  - rtc: s5m: select REGMAP_I2C (git-fixes).

  - rxrpc: Fix memory leak in rxrpc_lookup_local
    (bsc#1154353 bnc#1151927 5.3.9).

  - s390/vfio-ap: clean up vfio_ap resources when KVM
    pointer invalidated (git-fixes).

  - s390/vfio-ap: No need to disable IRQ after queue reset
    (git-fixes).

  - sched: Reenable interrupts in do_sched_yield()
    (git-fixes)

  - scsi: lpfc: Fix EEH encountering oops with NVMe traffic
    (bsc#1181958).

  - sh_eth: check sh_eth_cpu_data::cexcr when dumping
    registers (git-fixes).

  - sh_eth: check sh_eth_cpu_data::no_tx_cntrs when dumping
    registers (git-fixes).

  - sh_eth: check sh_eth_cpu_data::no_xdfar when dumping
    registers (git-fixes).

  - smp: Add source and destination CPUs to
    __call_single_data (bsc#1180846).

  - smsc95xx: avoid memory leak in smsc95xx_bind
    (git-fixes).

  - smsc95xx: check return value of smsc95xx_reset
    (git-fixes).

  - soc: aspeed: snoop: Add clock control logic (git-fixes).

  - spi: atmel: Put allocated master before return
    (git-fixes).

  - spi: pxa2xx: Fix the controller numbering for Wildcat
    Point (git-fixes).

  - spi: spi-synquacer: fix set_cs handling (git-fixes).

  - spi: stm32: properly handle 0 byte transfer (git-fixes).

  - squashfs: add more sanity checks in id lookup (git-fixes
    bsc#1182266).

  - squashfs: add more sanity checks in inode lookup
    (git-fixes bsc#1182267).

  - squashfs: add more sanity checks in xattr id lookup
    (git-fixes bsc#1182268).

  - staging: rtl8723bs: wifi_regd.c: Fix incorrect number of
    regulatory rules (git-fixes).

  - target: disallow emulate_legacy_capacity with RBD
    object-map (bsc#1177109).

  - team: set dev->needed_headroom in team_setup_by_port()
    (git-fixes).

  - tpm: Remove tpm_dev_wq_lock (git-fixes).

  - tpm_tis: Clean up locality release (git-fixes).

  - tpm_tis: Fix check_locality for correct locality
    acquisition (git-fixes).

  - tracing: Check length before giving out the filter
    buffer (git-fixes).

  - tracing: Do not count ftrace events in top level enable
    output (git-fixes).

  - tracing/kprobe: Fix to support kretprobe events on
    unloaded modules (git-fixes).

  - tracing/kprobes: Do the notrace functions check without
    kprobes on ftrace (git-fixes).

  - tun: fix return value when the number of iovs exceeds
    MAX_SKB_FRAGS (git-fixes).

  - ubifs: Fix error return code in
    ubifs_init_authentication() (bsc#1182459).

  - ubifs: Fix ubifs_tnc_lookup() usage in do_kill_orphans()
    (bsc#1182454).

  - ubifs: prevent creating duplicate encrypted filenames
    (bsc#1182457).

  - ubifs: ubifs_add_orphan: Fix a memory leak bug
    (bsc#1182456).

  - ubifs: ubifs_jnl_write_inode: Fix a memory leak bug
    (bsc#1182455). 

  - ubifs: wbuf: Do not leak kernel memory to flash
    (bsc#1182458).

  - Update config files: activate CONFIG_CSD_LOCK_WAIT_DEBUG
    for x86 (bsc#1180846).

  - Update config files: armv7hl: Set ledtrig-default-on as
    builtin (bsc#1182128)

  - Update config files: Set ledtrig-default-on as builtin
    (bsc#1182128)

  - USB: dwc2: Abort transaction after errors with unknown
    reason (git-fixes).

  - USB: dwc2: Fix endpoint direction check in
    ep_from_windex (git-fixes).

  - USB: dwc2: Make 'trimming xfer length' a debug message
    (git-fixes).

  - USB: dwc3: fix clock issue during resume in OTG mode
    (git-fixes).

  - USB: gadget: legacy: fix an error code in eth_bind()
    (git-fixes).

  - USB: gadget: u_audio: Free requests only after callback
    (git-fixes).

  - USB: musb: Fix runtime PM race in musb_queue_resume_work
    (git-fixes).

  - USB: quirks: add quirk to start video capture on ELMO
    L-12F document camera reliable (git-fixes).

  - USB: quirks: sort quirk entries (git-fixes).

  - USB: renesas_usbhs: Clear pipe running flag in
    usbhs_pkt_pop() (git-fixes).

  - USB: serial: cp210x: add new VID/PID for supporting
    Teraoka AD2000 (git-fixes).

  - USB: serial: cp210x: add pid/vid for WSDA-200-USB
    (git-fixes).

  - USB: serial: mos7720: fix error code in mos7720_write()
    (git-fixes).

  - USB: serial: mos7720: improve OOM-handling in
    read_mos_reg() (git-fixes).

  - USB: serial: mos7840: fix error code in mos7840_write()
    (git-fixes).

  - USB: serial: option: Adding support for Cinterion MV31
    (git-fixes).

  - USB: usblp: do not call usb_set_interface if there's a
    single alt (git-fixes).

  - veth: Adjust hard_start offset on redirect XDP frames
    (git-fixes).

  - vfs: Convert squashfs to use the new mount API
    (git-fixes bsc#1182265).

  - virtio_net: Fix error code in probe() (git-fixes).

  - virtio_net: Fix recursive call to cpus_read_lock()
    (git-fixes).

  - virtio_net: Keep vnet header zeroed if XDP is loaded for
    small buffer (git-fixes).

  - virt: vbox: Do not use wait_event_interruptible when
    called from kernel context (git-fixes).

  - vmxnet3: Remove buf_info from device accessible
    structures (bsc#1181671).

  - vxlan: fix memleak of fdb (git-fixes).

  - wext: fix NULL-ptr-dereference with cfg80211's lack of
    commit() (git-fixes).

  - writeback: Drop I_DIRTY_TIME_EXPIRE (bsc#1182460).

  - x86/alternatives: Sync bp_patching update for avoiding
    NULL pointer exception (bsc#1152489).

  - x86/apic: Add extra serialization for non-serializing
    MSRs (bsc#1152489).

  - x86/apic: Support 15 bits of APIC ID in IOAPIC/MSI where
    available (bsc#1181259, jsc#ECO-3191).

  - x86/ioapic: Handle Extended Destination ID field in RTE
    (bsc#1181259, jsc#ECO-3191).

  - x86/kvm: Add KVM_FEATURE_MSI_EXT_DEST_ID (bsc#1181259,
    jsc#ECO-3191).

  - x86/kvm: Reserve KVM_FEATURE_MSI_EXT_DEST_ID
    (bsc#1181259 jsc#ECO-3191).

  - x86/msi: Only use high bits of MSI address for DMAR unit
    (bsc#1181259, jsc#ECO-3191).

  - xen/netback: avoid race in
    xenvif_rx_ring_slots_available() (bsc#1065600).

  - xen/netback: fix spurious event detection for common
    event case (bsc#1182175).

  - xfs: ensure inobt record walks always make forward
    progress (git-fixes bsc#1182272).

  - xfs: fix an ABBA deadlock in xfs_rename (git-fixes
    bsc#1182558).

  - xfs: fix parent pointer scrubber bailing out on
    unallocated inodes (git-fixes bsc#1182276).

  - xfs: fix the forward progress assertion in
    xfs_iwalk_run_callbacks (git-fixes bsc#1182430).

  - xfs: fix the minrecs logic when dealing with inode root
    child blocks (git-fixes bsc#1182273).

  - xfs: ratelimit xfs_discard_page messages (bsc#1182283).

  - xfs: reduce quota reservation when doing a dax unwritten
    extent conversion (git-fixes bsc#1182561).

  - xfs: return corresponding errcode if
    xfs_initialize_perag() fail (git-fixes bsc#1182275).

  - xfs: scrub should mark a directory corrupt if any
    entries cannot be iget'd (git-fixes bsc#1182278).

  - xfs: strengthen rmap record flags checking (git-fixes
    bsc#1182271).

  - xhci: fix bounce buffer usage for non-sg list case
    (git-fixes).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182676");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182856");
  script_set_attribute(attribute:"see_also", value:"https://github.com/openSUSE/openSUSE-release-tools/issues/2439");
  script_set_attribute(attribute:"solution", value:
"Update the affected the Linux Kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29368");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-26930");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-rebuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-5.3.18-lp152.66.2.lp152.8.23.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-rebuild-5.3.18-lp152.66.2.lp152.8.23.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.66.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.66.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-debuginfo / kernel-debug-debugsource / etc");
}
