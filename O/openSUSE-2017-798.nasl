#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-798.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101348);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000365", "CVE-2017-7518");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-798) (Stack Clash)");
  script_summary(english:"Check for the openSUSE-2017-798 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to 4.4.74 to receive various
security and bugfixes.

This update fixes some long standing btrfs issues.

The following security bugs were fixed :

  - CVE-2017-7518: A KVM debug exception in the syscall
    handling was fixed which might have been used for local
    privilege escalation. (bnc#1045922).

  - CVE-2017-1000365: The Linux Kernel imposes a size
    restriction on the arguments and environmental strings
    passed through RLIMIT_STACK/RLIM_INFINITY (1/4 of the
    size), but did not take the argument and environment
    pointers into account, which allowed attackers to bypass
    this limitation. (bnc#1039354).

The following non-security bugs were fixed :

  - bluetooth: hidp: fix possible might sleep error in
    hidp_session_thread (bsc#1031784).

  - btrfs: disable possible cause of premature ENOSPC
    (bsc#1040182)

  - btrfs: Manually implement device_total_bytes
    getter/setter (bsc#1043912).

  - btrfs: Round down values which are written for
    total_bytes_size (bsc#1043912).

  - drm/i915: Serialize GTT/Aperture accesses on BXT
    (bsc#1046821).

  - Fix kABI breakage by KVM CVE fix (bsc#1045922).

  - hpsa: limit transfer length to 1MB (bsc#1025461).

  - hwpoison, memcg: forcibly uncharge LRU pages
    (bnc#1046105).

  - ibmvnic: Fix assignment of RX/TX IRQ's (bsc#1046589).

  - iw_cxgb4: Fix error return code in c4iw_rdev_open()
    (bsc#1026570).

  - iwlwifi: 8000: fix MODULE_FIRMWARE input (FATE#321353,
    FATE#323335).

  - iwlwifi: 9000: increase the number of queues
    (FATE#321353, FATE#323335).

  - iwlwifi: add device ID for 8265 (FATE#321353,
    FATE#323335).

  - iwlwifi: add device IDs for the 8265 device
    (FATE#321353, FATE#323335).

  - iwlwifi: add disable_11ac module param (FATE#321353,
    FATE#323335).

  - iwlwifi: add new 3168 series devices support
    (FATE#321353, FATE#323335).

  - iwlwifi: add new 8260 PCI IDs (FATE#321353,
    FATE#323335).

  - iwlwifi: add new 8265 (FATE#321353, FATE#323335).

  - iwlwifi: add new 8265 series PCI ID (FATE#321353,
    FATE#323335).

  - iwlwifi: Add new PCI IDs for 9260 and 5165 series
    (FATE#321353, FATE#323335).

  - iwlwifi: Add PCI IDs for the new 3168 series
    (FATE#321353, FATE#323335).

  - iwlwifi: Add PCI IDs for the new series 8165
    (FATE#321353, FATE#323335).

  - iwlwifi: add support for 12K Receive Buffers
    (FATE#321353, FATE#323335).

  - iwlwifi: add support for getting HW address from CSR
    (FATE#321353, FATE#323335).

  - iwlwifi: avoid d0i3 commands when no/init ucode is
    loaded (FATE#321353, FATE#323335).

  - iwlwifi: bail out in case of bad trans state
    (FATE#321353, FATE#323335).

  - iwlwifi: block the queues when we send ADD_STA for uAPSD
    (FATE#321353, FATE#323335).

  - iwlwifi: change the Intel Wireless email address
    (FATE#321353, FATE#323335).

  - iwlwifi: change the Intel Wireless email address
    (FATE#321353, FATE#323335).

  - iwlwifi: check for valid ethernet address provided by
    OEM (FATE#321353, FATE#323335).

  - iwlwifi: clean up transport debugfs handling
    (FATE#321353, FATE#323335).

  - iwlwifi: clear ieee80211_tx_info->driver_data in the
    op_mode (FATE#321353, FATE#323335).

  - iwlwifi: Document missing module options (FATE#321353,
    FATE#323335).

  - iwlwifi: dump prph registers in a common place for all
    transports (FATE#321353, FATE#323335).

  - iwlwifi: dvm: advertise NETIF_F_SG (FATE#321353,
    FATE#323335).

  - iwlwifi: dvm: fix compare_const_fl.cocci warnings
    (FATE#321353, FATE#323335).

  - iwlwifi: dvm: handle zero brightness for wifi LED
    (FATE#321353, FATE#323335).

  - iwlwifi: dvm: remove a wrong dependency on m
    (FATE#321353, FATE#323335).

  - iwlwifi: dvm: remove Kconfig default (FATE#321353,
    FATE#323335).

  - iwlwifi: dvm: remove stray debug code (FATE#321353,
    FATE#323335).

  - iwlwifi: export the _no_grab version of PRPH IO
    functions (FATE#321353, FATE#323335).

  - iwlwifi: expose fw usniffer mode to more utilities
    (FATE#321353, FATE#323335).

  - iwlwifi: fix double hyphen in MODULE_FIRMWARE for 8000
    (FATE#321353, FATE#323335).

  - iwlwifi: Fix firmware name maximum length definition
    (FATE#321353, FATE#323335).

  - iwlwifi: fix name of ucode loaded for 8265 series
    (FATE#321353, FATE#323335).

  - iwlwifi: fix printf specifier (FATE#321353,
    FATE#323335).

  - iwlwifi: generalize d0i3_entry_timeout module parameter
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: adapt the firmware assert log to new
    firmware (FATE#321353, FATE#323335).

  - iwlwifi: mvm: add 9000-series RX API (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: add 9000 series RX processing
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: add a non-trigger window to fw dbg
    triggers (FATE#321353, FATE#323335).

  - iwlwifi: mvm: add an option to start rs from HT/VHT
    rates (FATE#321353, FATE#323335).

  - iwlwifi: mvm: Add a station in monitor mode
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: add bt rrc and ttc to debugfs
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: add bt settings to debugfs (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: add ctdp operations to debugfs
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: add CT-KILL notification (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: add debug print if scan config is ignored
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: add extended dwell time (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: add new ADD_STA command version
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: Add P2P client snoozing (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: add registration to cooling device
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: add registration to thermal zone
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: add support for negative temperatures
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: add tlv for multi queue rx support
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: add trigger for firmware dump upon TDLS
    events (FATE#321353, FATE#323335).

  - iwlwifi: mvm: add trigger for firmware dump upon TX
    response status (FATE#321353, FATE#323335).

  - iwlwifi: mvm: advertise NETIF_F_SG (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: Align bt-coex priority with requirements
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: allow to disable beacon filtering for
    AP/GO interface (FATE#321353, FATE#323335).

  - iwlwifi: mvm: avoid harmless -Wmaybe-uninialized warning
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: avoid panics with thermal device usage
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: avoid to WARN about gscan capabilities
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: bail out if CTDP start operation fails
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: bump firmware API to 21 (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: bump max API to 20 (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: change access to ieee80211_hdr
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: change iwl_mvm_get_key_sta_id() to return
    the station (FATE#321353, FATE#323335).

  - iwlwifi: mvm: change mcc update API (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: change name of iwl_mvm_d3_update_gtk
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: Change number of associated stations when
    station becomes associated (FATE#321353, FATE#323335).

  - iwlwifi: mvm: change protocol offload flows
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: change the check for ADD_STA status
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: check FW's response for nvm access write
    cmd (FATE#321353, FATE#323335).

  - iwlwifi: mvm: check iwl_mvm_wowlan_config_key_params()
    return value (FATE#321353, FATE#323335).

  - iwlwifi: mvm: check minimum temperature notification
    length (FATE#321353, FATE#323335).

  - iwlwifi: mvm: cleanup roc te on restart cleanup
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: Configure fragmented scan for scheduled
    scan (FATE#321353, FATE#323335).

  - iwlwifi: mvm: configure scheduled scan according to
    traffic conditions (FATE#321353, FATE#323335).

  - iwlwifi: mvm: constify the parameters of a few functions
    in fw-dbg.c (FATE#321353, FATE#323335).

  - iwlwifi: mvm: Disable beacon storing in D3 when WOWLAN
    configured (FATE#321353, FATE#323335).

  - iwlwifi: mvm: disable DQA support (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: do not ask beacons when P2P GO vif and no
    assoc sta (FATE#321353, FATE#323335).

  - iwlwifi: mvm: do not keep an mvm ref when the interface
    is down (FATE#321353, FATE#323335).

  - iwlwifi: mvm: do not let NDPs mess the packet tracking
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: do not restart HW if suspend fails with
    unified image (FATE#321353, FATE#323335).

  - iwlwifi: mvm: Do not switch to D3 image on suspend
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: do not try to offload AES-CMAC in AP/IBSS
    modes (FATE#321353, FATE#323335).

  - iwlwifi: mvm: drop low_latency_agg_frame_cnt_limit
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: dump more registers upon error
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: dump the radio registers when the firmware
    crashes (FATE#321353, FATE#323335).

  - iwlwifi: mvm: enable L3 filtering (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: Enable MPLUT only on supported hw
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: enable VHT MU-MIMO for supported hardware
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: extend time event duration (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: fix accessing NULL pointer during fw dump
    collection (FATE#321353, FATE#323335).

  - iwlwifi: mvm: fix d3_test with unified D0/D3 images
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: fix debugfs signedness warning
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: fix extended dwell time (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: fix incorrect fallthrough in
    iwl_mvm_check_running_scans() (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: fix memory leaks in error paths upon fw
    error dump (FATE#321353, FATE#323335).

  - iwlwifi: mvm: fix netdetect starting/stopping for
    unified images (FATE#321353, FATE#323335).

  - iwlwifi: mvm: fix RSS key sizing (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: fix unregistration of thermal in some
    error flows (FATE#321353, FATE#323335).

  - iwlwifi: mvm: flush all used TX queues before suspending
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: forbid U-APSD for P2P Client if the
    firmware does not support it (FATE#321353, FATE#323335).

  - iwlwifi: mvm: handle pass all scan reporting
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: ignore LMAC scan notifications when
    running UMAC scans (FATE#321353, FATE#323335).

  - iwlwifi: mvm: infrastructure for frame-release message
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: kill iwl_mvm_enable_agg_txq (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: let the firmware choose the antenna for
    beacons (FATE#321353, FATE#323335).

  - iwlwifi: mvm: make collecting fw debug data optional
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: move fw-dbg code to separate file
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: only release the trans ref if d0i3 is
    supported in fw (FATE#321353, FATE#323335).

  - iwlwifi: mvm: prepare the code towards TSO
    implementation (FATE#321353, FATE#323335).

  - iwlwifi: mvm: refactor d3 key update functions
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: refactor the way fw_key_table is handled
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: remove an extra tab (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: Remove bf_vif from iwl_power_vifs
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: Remove iwl_mvm_update_beacon_abort
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: remove redundant d0i3 flag from the config
    struct (FATE#321353, FATE#323335).

  - iwlwifi: mvm: remove shadowing variable (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: remove stray nd_config element
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: remove the vif parameter of
    iwl_mvm_configure_bcast_filter() (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: remove unnecessary check in
    iwl_mvm_is_d0i3_supported() (FATE#321353, FATE#323335).

  - iwlwifi: mvm: remove useless WARN_ON and rely on
    cfg80211's combination (FATE#321353, FATE#323335).

  - iwlwifi: mvm: report wakeup for wowlan (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: reset mvm->scan_type when firmware is
    started (FATE#321353, FATE#323335).

  - iwlwifi: mvm: return the cooling state index instead of
    the budget (FATE#321353, FATE#323335).

  - iwlwifi: mvm: ROC: cleanup time event info on FW failure
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: ROC: Extend the ROC max delay duration &
    limit ROC duration (FATE#321353, FATE#323335).

  - iwlwifi: mvm: rs: fix a potential out of bounds access
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: rs: fix a theoretical access to
    uninitialized array elements (FATE#321353, FATE#323335).

  - iwlwifi: mvm: rs: fix a warning message (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: rs: fix TPC action decision algorithm
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: rs: fix TPC statistics handling
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: Send power command on
    BSS_CHANGED_BEACON_INFO if needed (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: set default new STA as non-aggregated
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: set the correct amsdu enum values
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: set the correct descriptor size for
    tracing (FATE#321353, FATE#323335).

  - iwlwifi: mvm: small update in the firmware API
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: support A-MSDU in A-MPDU (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: support beacon storing (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: support description for user triggered fw
    dbg collection (FATE#321353, FATE#323335).

  - iwlwifi: mvm: support rss queues configuration command
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: Support setting continuous recording debug
    mode (FATE#321353, FATE#323335).

  - iwlwifi: mvm: support setting minimum quota from debugfs
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: support sw queue start/stop from mvm
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: take care of padded packets (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: take the transport ref back when leaving
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: track low-latency sources separately
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: update GSCAN capabilities (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: update ucode status before stopping device
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: use build-time assertion for fw trigger ID
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: use firmware station lookup, combine code
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: various trivial cleanups (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: writing zero bytes to debugfs causes a
    crash (FATE#321353, FATE#323335).

  - iwlwifi: nvm: fix loading default NVM file (FATE#321353,
    FATE#323335).

  - iwlwifi: nvm: fix up phy section when reading it
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: add 9000 series multi queue rx DMA
    support (FATE#321353, FATE#323335).

  - iwlwifi: pcie: add infrastructure for multi-queue rx
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: add initial RTPM support for PCI
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: Add new configuration to enable MSIX
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: add pm_prepare and pm_complete ops
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: add RTPM support when wifi is enabled
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: aggregate Flow Handler configuration
    writes (FATE#321353, FATE#323335).

  - iwlwifi: pcie: allow the op_mode to block the tx queues
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: allow to pretend to have Tx CSUM for
    debug (FATE#321353, FATE#323335).

  - iwlwifi: pcie: avoid restocks inside rx loop if not
    emergency (FATE#321353, FATE#323335).

  - iwlwifi: pcie: buffer packets to avoid overflowing Tx
    queues (FATE#321353, FATE#323335).

  - iwlwifi: pcie: build an A-MSDU using TSO core
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: configure more RFH settings (FATE#321353,
    FATE#323335).

  - iwlwifi: pcie: detect and workaround invalid write ptr
    behavior (FATE#321353, FATE#323335).

  - iwlwifi: pcie: do not increment / decrement a bool
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: enable interrupts before releasing the
    NIC's CPU (FATE#321353, FATE#323335).

  - iwlwifi: pcie: enable multi-queue rx path (FATE#321353,
    FATE#323335).

  - iwlwifi: pcie: extend device reset delay (FATE#321353,
    FATE#323335).

  - iwlwifi: pcie: fine tune number of rxbs (FATE#321353,
    FATE#323335).

  - iwlwifi: pcie: fix a race in firmware loading flow
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: fix erroneous return value (FATE#321353,
    FATE#323335).

  - iwlwifi: pcie: fix global table size (FATE#321353,
    FATE#323335).

  - iwlwifi: pcie: fix identation in trans.c (FATE#321353,
    FATE#323335).

  - iwlwifi: pcie: fix RF-Kill vs. firmware load race
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: forbid RTPM on device removal
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: mark command queue lock with separate
    lockdep class (FATE#321353, FATE#323335).

  - iwlwifi: pcie: prevent skbs shadowing in
    iwl_trans_pcie_reclaim (FATE#321353, FATE#323335).

  - iwlwifi: pcie: refactor RXBs reclaiming code
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: remove ICT allocation message
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: remove pointer from debug message
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: re-organize code towards TSO
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: set RB chunk size back to 64
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: update iwl_mpdu_desc fields (FATE#321353,
    FATE#323335).

  - iwlwifi: print index in api/capa flags parsing message
    (FATE#321353, FATE#323335).

  - iwlwifi: refactor the code that reads the MAC address
    from the NVM (FATE#321353, FATE#323335).

  - iwlwifi: remove IWL_DL_LED (FATE#321353, FATE#323335).

  - iwlwifi: remove unused parameter from grab_nic_access
    (FATE#321353, FATE#323335).

  - iwlwifi: replace d0i3_mode and wowlan_d0i3 with more
    generic variables (FATE#321353, FATE#323335).

  - iwlwifi: set max firmware version of 7265 to 17
    (FATE#321353, FATE#323335).

  - iwlwifi: support ucode with d0 unified image - regular
    and usniffer (FATE#321353, FATE#323335).

  - iwlwifi: trans: make various conversion macros inlines
    (FATE#321353, FATE#323335).

  - iwlwifi: trans: support a callback for ASYNC commands
    (FATE#321353, FATE#323335).

  - iwlwifi: treat iwl_parse_nvm_data() MAC addr as little
    endian (FATE#321353, FATE#323335).

  - iwlwifi: tt: move ucode_loaded check under mutex
    (FATE#321353, FATE#323335).

  - iwlwifi: uninline iwl_trans_send_cmd (FATE#321353,
    FATE#323335).

  - iwlwifi: update host command messages to new format
    (FATE#321353, FATE#323335).

  - iwlwifi: Update PCI IDs for 8000 and 9000 series
    (FATE#321353, FATE#323335).

  - iwlwifi: update support for 3168 series firmware and NVM
    (FATE#321353, FATE#323335).

  - iwlwifi: various comments and code cleanups
    (FATE#321353, FATE#323335).

  - kabi: ignore fs_info parameter for tracepoints that
    didn't have it (bsc#1044912).

  - kabi/severities: ignore kABi changes in iwlwifi stuff
    itself

  - powerpc/ftrace: Pass the correct stack pointer for
    DYNAMIC_FTRACE_WITH_REGS (FATE#322421).

  - printk: Correctly handle preemption in console_unlock()
    (bsc#1046434).

  - printk/xen: Force printk sync mode when migrating Xen
    guest (bsc#1043347).

  - RDMA/iw_cxgb4: Always wake up waiter in
    c4iw_peer_abort_intr() (bsc#1026570).

  - smartpqi: limit transfer length to 1MB (bsc#1025461).

  - tty: Destroy ldisc instance on hangup (bnc#1043488).

  - tty: Fix ldisc crash on reopened tty (bnc#1043488).

  - tty: Handle NULL tty->ldisc (bnc#1043488).

  - tty: Move tty_ldisc_kill() (bnc#1043488).

  - tty: Prepare for destroying line discipline on hangup
    (bnc#1043488).

  - tty: Refactor tty_ldisc_reinit() for reuse
    (bnc#1043488).

  - tty: Reset c_line from driver's init_termios
    (bnc#1043488).

  - tty: Simplify tty_set_ldisc() exit handling
    (bnc#1043488).

  - tty: Use 'disc' for line discipline index name
    (bnc#1043488).

  - Update config files: add CONFIG_IWLWIFI_PCIE_RTPM=y
    (FATE#323335)

  - Update patches.fixes/nfs-svc-rdma.fix (bsc#1044854). Fix
    bsc reference

  - Update
    patches.fixes/xfs-split-default-quota-limits-by-quota-ty
    pe.patch (bsc#1040941). Fix the bug nr used."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046821"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.74-18.20.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.74-18.20.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.74-18.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.74-18.20.1") ) flag++;

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
