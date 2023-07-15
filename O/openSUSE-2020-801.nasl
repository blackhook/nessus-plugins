#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-801.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138679);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2018-1000199", "CVE-2019-19462", "CVE-2019-20806", "CVE-2019-20812", "CVE-2019-9455", "CVE-2020-0543", "CVE-2020-10690", "CVE-2020-10711", "CVE-2020-10720", "CVE-2020-10732", "CVE-2020-10751", "CVE-2020-10757", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-12114", "CVE-2020-12464", "CVE-2020-12652", "CVE-2020-12653", "CVE-2020-12654", "CVE-2020-12655", "CVE-2020-12656", "CVE-2020-12657", "CVE-2020-12659", "CVE-2020-12769", "CVE-2020-13143");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-801)");
  script_summary(english:"Check for the openSUSE-2020-801 patch");

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

  - CVE-2020-0543: Fixed a side channel attack against
    special registers which could have resulted in leaking
    of read values to cores other than the one which called
    it. This attack is known as Special Register Buffer Data
    Sampling (SRBDS) or 'CrossTalk' (bsc#1154824).

  - CVE-2018-1000199: Fixed a potential local code execution
    via ptrace (bsc#1089895).

  - CVE-2019-19462: relay_open in kernel/relay.c allowed
    local users to cause a denial of service (such as relay
    blockage) by triggering a NULL alloc_percpu result
    (bnc#1158265).

  - CVE-2019-20806: Fixed a NULL pointer dereference in
    tw5864_handle_frame() which may had lead to denial of
    service (bsc#1172199).

  - CVE-2019-20812: The prb_calc_retire_blk_tmo() function
    in net/packet/af_packet.c can result in a denial of
    service (CPU consumption and soft lockup) in a certain
    failure case involving TPACKET_V3, aka CID-b43d1f9f7067
    (bnc#1172453).

  - CVE-2019-9455: Fixed a pointer leak due to a WARN_ON
    statement in a video driver. This could lead to local
    information disclosure with System execution privileges
    needed (bsc#1170345).

  - CVE-2020-10690: Fixed the race between the release of
    ptp_clock and cdev (bsc#1170056).

  - CVE-2020-10711: Fixed a NULL pointer dereference in
    SELinux subsystem which could have allowed a remote
    network user to crash the kernel resulting in a denial
    of service (bsc#1171191).

  - CVE-2020-10720: Fixed a use-after-free read in
    napi_gro_frags() (bsc#1170778).

  - CVE-2020-10732: Fixed kernel data leak in userspace
    coredumps due to uninitialized data (bsc#1171220).

  - CVE-2020-10751: Fixed an improper implementation in
    SELinux LSM hook where it was assumed that an skb would
    only contain a single netlink message (bsc#1171189).

  - CVE-2020-10757: Fixed an issue where remaping hugepage
    DAX to anon mmap could have caused user PTE access
    (bsc#1172317).

  - CVE-2020-11608: An issue was discovered in
    drivers/media/usb/gspca/ov519.c that allowed NULL
    pointer dereferences in ov511_mode_init_regs and
    ov518_mode_init_regs when there are zero endpoints, aka
    CID-998912346c0d (bnc#1168829).

  - CVE-2020-11609: An issue was discovered in the stv06xx
    subsystem in drivers/media/usb/gspca/stv06xx/stv06xx.c
    and drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c
    mishandle invalid descriptors, as demonstrated by a NULL
    pointer dereference, aka CID-485b06aadb93 (bnc#1168854).

  - CVE-2020-12114: Fixed a pivot_root race condition which
    could have allowed local users to cause a denial of
    service (panic) by corrupting a mountpoint reference
    counter (bsc#1171098).

  - CVE-2020-12464: Fixed a use-after-free due to a transfer
    without a reference (bsc#1170901).

  - CVE-2020-12652: Fixed an issue which could have allowed
    local users to hold an incorrect lock during the ioctl
    operation and trigger a race condition (bsc#1171218).

  - CVE-2020-12653: Fixed an issue in the wifi driver which
    could have allowed local users to gain privileges or
    cause a denial of service (bsc#1171195).

  - CVE-2020-12654: Fixed an issue in he wifi driver which
    could have allowed a remote AP to trigger a heap-based
    buffer overflow (bsc#1171202).

  - CVE-2020-12655: Fixed an issue which could have allowed
    attackers to trigger a sync of excessive duration via an
    XFS v5 image with crafted metadata (bsc#1171217).

  - CVE-2020-12656: Fixed an improper handling of certain
    domain_release calls leadingch could have led to a
    memory leak (bsc#1171219).

  - CVE-2020-12657: An a use-after-free in
    block/bfq-iosched.c (bsc#1171205).

  - CVE-2020-12659: Fixed an out-of-bounds write (by a user
    with the CAP_NET_ADMIN capability) due to improper
    headroom validation (bsc#1171214).

  - CVE-2020-12769: Fixed an issue which could have allowed
    attackers to cause a panic via concurrent calls to
    dw_spi_irq and dw_spi_transfer_one (bsc#1171983).

  - CVE-2020-13143: Fixed an out-of-bounds read in
    gadget_dev_desc_UDC_store in
    drivers/usb/gadget/configfs.c (bsc#1171982).

The following non-security bugs were fixed :

  - ACPI: CPPC: Fix reference count leak in
    acpi_cppc_processor_probe() (bsc#1051510).

  - ACPI: sysfs: Fix reference count leak in
    acpi_sysfs_add_hotplug_profile() (bsc#1051510).

  - acpi/x86: ignore unspecified bit positions in the ACPI
    global lock field (bsc#1051510).

  - Add br_netfilter to kernel-default-base (bsc#1169020)

  - agp/intel: Reinforce the barrier after GTT updates
    (bsc#1051510).

  - ALSA: ctxfi: Remove unnecessary cast in kfree
    (bsc#1051510).

  - ALSA: doc: Document PC Beep Hidden Register on Realtek
    ALC256 (bsc#1051510).

  - ALSA: dummy: Fix PCM format loop in proc output
    (bsc#1111666).

  - ALSA: hda: Add driver blacklist (bsc#1051510).

  - ALSA: hda: Always use jackpoll helper for jack update
    after resume (bsc#1051510).

  - ALSA: hda: call runtime_allow() for all hda controllers
    (bsc#1051510).

  - ALSA: hda: Do not release card at firmware loading error
    (bsc#1051510).

  - ALSA: hda: Explicitly permit using autosuspend if
    runtime PM is supported (bsc#1051510).

  - ALSA: hda/hdmi: fix race in monitor detection during
    probe (bsc#1051510).

  - ALSA: hda/hdmi: fix without unlocked before return
    (bsc#1051510).

  - ALSA: hda: Honor PM disablement in PM freeze and
    thaw_noirq ops (bsc#1051510).

  - ALSA: hda: Keep the controller initialization even if no
    codecs found (bsc#1051510).

  - ALSA: hda: Match both PCI ID and SSID for driver
    blacklist (bsc#1111666).

  - ALSA: hda/realtek - Add a model for Thinkpad T570
    without DAC workaround (bsc#1172017).

  - ALSA: hda/realtek - Add COEF workaround for ASUS ZenBook
    UX431DA (git-fixes).

  - ALSA: hda/realtek - Add HP new mute led supported for
    ALC236 (git-fixes).

  - ALSA: hda/realtek - Add more fixup entries for Clevo
    machines (git-fixes).

  - ALSA: hda/realtek - Add new codec supported for ALC245
    (bsc#1051510).

  - ALSA: hda/realtek - Add new codec supported for ALC287
    (git-fixes).

  - ALSA: hda/realtek: Add quirk for Samsung Notebook
    (git-fixes).

  - ALSA: hda/realtek - Add supported new mute Led for HP
    (git-fixes).

  - ALSA: hda/realtek - Enable headset mic of ASUS GL503VM
    with ALC295 (git-fixes).

  - ALSA: hda/realtek - Enable headset mic of ASUS UX550GE
    with ALC295 (git-fixes).

  - ALSA: hda/realtek: Enable headset mic of ASUS UX581LV
    with ALC295 (git-fixes).

  - ALSA: hda/realtek - Enable the headset mic on Asus
    FX505DT (bsc#1051510).

  - ALSA: hda/realtek - Fix S3 pop noise on Dell Wyse
    (git-fixes).

  - ALSA: hda/realtek - Fix silent output on Gigabyte X570
    Aorus Xtreme (bsc#1111666).

  - ALSA: hda/realtek - Fix unexpected init_amp override
    (bsc#1051510).

  - ALSA: hda/realtek - Limit int mic boost for Thinkpad
    T530 (git-fixes bsc#1171293).

  - ALSA: hda/realtek - Two front mics on a Lenovo
    ThinkCenter (bsc#1051510).

  - ALSA: hda: Release resources at error in delayed probe
    (bsc#1051510).

  - ALSA: hda: Remove ASUS ROG Zenith from the blacklist
    (bsc#1051510).

  - ALSA: hda: Skip controller resume if not needed
    (bsc#1051510).

  - ALSA: hwdep: fix a left shifting 1 by 31 UB bug
    (git-fixes).

  - ALSA: iec1712: Initialize STDSP24 properly when using
    the model=staudio option (git-fixes).

  - ALSA: opti9xx: shut up gcc-10 range warning
    (bsc#1051510).

  - ALSA: pcm: fix incorrect hw_base increase (git-fixes).

  - ALSA: pcm: oss: Place the plugin buffer overflow checks
    correctly (bsc#1170522).

  - ALSA: rawmidi: Fix racy buffer resize under concurrent
    accesses (git-fixes).

  - ALSA: usb-audio: Add connector notifier delegation
    (bsc#1051510).

  - ALSA: usb-audio: Add control message quirk delay for
    Kingston HyperX headset (git-fixes).

  - ALSA: usb-audio: add mapping for ASRock TRX40 Creator
    (git-fixes).

  - ALSA: usb-audio: Add mixer workaround for TRX40 and co
    (bsc#1051510).

  - ALSA: usb-audio: Add quirk for Focusrite Scarlett 2i2
    (bsc#1051510).

  - ALSA: usb-audio: Add static mapping table for
    ALC1220-VB-based mobos (bsc#1051510).

  - ALSA: usb-audio: Apply async workaround for Scarlett 2i4
    2nd gen (bsc#1051510).

  - ALSA: usb-audio: Check mapping at creating connector
    controls, too (bsc#1051510).

  - ALSA: usb-audio: Correct a typo of NuPrime DAC-10 USB ID
    (bsc#1051510).

  - ALSA: usb-audio: Do not create jack controls for PCM
    terminals (bsc#1051510).

  - ALSA: usb-audio: Do not override ignore_ctl_error value
    from the map (bsc#1051510).

  - ALSA: usb-audio: Filter error from connector kctl ops,
    too (bsc#1051510).

  - ALSA: usb-audio: Fix usb audio refcnt leak when getting
    spdif (bsc#1051510).

  - ALSA: usb-audio: mixer: volume quirk for ESS Technology
    Asus USB DAC (git-fixes).

  - ALSA: usb-audio: Quirks for Gigabyte TRX40 Aorus Master
    onboard audio (git-fixes).

  - ALSA: usx2y: Fix potential NULL dereference
    (bsc#1051510).

  - ASoC: codecs: hdac_hdmi: Fix incorrect use of
    list_for_each_entry (bsc#1051510).

  - ASoC: dapm: connect virtual mux with default value
    (bsc#1051510).

  - ASoC: dapm: fixup dapm kcontrol widget (bsc#1051510).

  - ASoC: dpcm: allow start or stop during pause for backend
    (bsc#1051510).

  - ASoC: fix regwmask (bsc#1051510).

  - ASoC: msm8916-wcd-digital: Reset RX interpolation path
    after use (bsc#1051510).

  - ASoC: samsung: Prevent clk_get_rate() calls in atomic
    context (bsc#1111666).

  - ASoC: topology: Check return value of pcm_new_ver
    (bsc#1051510).

  - ASoC: topology: use name_prefix for new kcontrol
    (bsc#1051510).

  - b43legacy: Fix case where channel status is corrupted
    (bsc#1051510).

  - batman-adv: fix batadv_nc_random_weight_tq (git-fixes).

  - batman-adv: Fix refcnt leak in
    batadv_show_throughput_override (git-fixes).

  - batman-adv: Fix refcnt leak in
    batadv_store_throughput_override (git-fixes).

  - batman-adv: Fix refcnt leak in batadv_v_ogm_process
    (git-fixes).

  - bcache: avoid unnecessary btree nodes flushing in
    btree_flush_write() (git fixes (block drivers)).

  - bcache: fix incorrect data type usage in
    btree_flush_write() (git fixes (block drivers)).

  - bcache: Revert 'bcache: shrink btree node cache after
    bch_btree_check()' (git fixes (block drivers)).

  - blk-mq: honor IO scheduler for multiqueue devices
    (bsc#1165478).

  - blk-mq: simplify blk_mq_make_request() (bsc#1165478).

  - block/drbd: delete invalid function drbd_md_mark_dirty_
    (bsc#1171527).

  - block: drbd: remove a stray unlock in
    __drbd_send_protocol() (bsc#1171599).

  - block: fix busy device checking in blk_drop_partitions
    again (bsc#1171948).

  - block: fix busy device checking in blk_drop_partitions
    (bsc#1171948).

  - block: fix memleak of bio integrity data (git fixes
    (block drivers)).

  - block: remove the bd_openers checks in
    blk_drop_partitions (bsc#1171948).

  - bnxt_en: fix memory leaks in bnxt_dcbnl_ieee_getets()
    (networking-stable-20_03_28).

  - bnxt_en: Reduce BNXT_MSIX_VEC_MAX value to supported CQs
    per PF (bsc#1104745).

  - bnxt_en: reinitialize IRQs when MTU is modified
    (networking-stable-20_03_14).

  - bnxt_en: Return error if bnxt_alloc_ctx_mem() fails
    (bsc#1104745 ).

  - bnxt_en: Return error when allocating zero size context
    memory (bsc#1104745).

  - bonding/alb: make sure arp header is pulled before
    accessing it (networking-stable-20_03_14).

  - bpf: Fix sk_psock refcnt leak when receiving message
    (bsc#1083647).

  - bpf: Forbid XADD on spilled pointers for unprivileged
    users (bsc#1083647).

  - brcmfmac: abort and release host after error
    (bsc#1051510).

  - btrfs: fix deadlock with memory reclaim during scrub
    (bsc#1172127).

  - btrfs: fix log context list corruption after rename
    whiteout error (bsc#1172342).

  - btrfs: fix partial loss of prealloc extent past i_size
    after fsync (bsc#1172343).

  - btrfs: relocation: add error injection points for
    cancelling balance (bsc#1171417).

  - btrfs: relocation: Check cancel request after each data
    page read (bsc#1171417).

  - btrfs: relocation: Check cancel request after each
    extent found (bsc#1171417).

  - btrfs: relocation: Clear the DEAD_RELOC_TREE bit for
    orphan roots to prevent runaway balance (bsc#1171417).

  - btrfs: relocation: Fix reloc root leakage and the NULL
    pointer reference caused by the leakage (bsc#1171417).

  - btrfs: relocation: Work around dead relocation stage
    loop (bsc#1171417).

  - btrfs: reloc: clear DEAD_RELOC_TREE bit for orphan roots
    to prevent runaway balance (bsc#1171417 bsc#1160947
    bsc#1172366).

  - btrfs: reloc: fix reloc root leak and NULL pointer
    dereference (bsc#1171417 bsc#1160947 bsc#1172366).

  - btrfs: setup a nofs context for memory allocation at
    btrfs_create_tree() (bsc#1172127).

  - btrfs: setup a nofs context for memory allocation at
    __btrfs_set_acl (bsc#1172127).

  - btrfs: use nofs context when initializing security
    xattrs to avoid deadlock (bsc#1172127).

  - can: add missing attribute validation for termination
    (networking-stable-20_03_14).

  - cdc-acm: close race betrween suspend() and acm_softint
    (git-fixes).

  - cdc-acm: introduce a cool down (git-fixes).

  - ceph: check if file lock exists before sending unlock
    request (bsc#1168789).

  - ceph: demote quotarealm lookup warning to a debug
    message (bsc#1171692).

  - ceph: fix double unlock in handle_cap_export()
    (bsc#1171694).

  - ceph: fix endianness bug when handling MDS session
    feature bits (bsc#1171695).

  - cgroup, netclassid: periodically release file_lock on
    classid updating (networking-stable-20_03_14).

  - cifs: Allocate crypto structures on the fly for
    calculating signatures of incoming packets
    (bsc#1144333).

  - cifs: Allocate encryption header through kmalloc
    (bsc#1144333).

  - cifs: allow unlock flock and OFD lock across fork
    (bsc#1144333).

  - cifs: check new file size when extending file by
    fallocate (bsc#1144333).

  - cifs: cifspdu.h: Replace zero-length array with
    flexible-array member (bsc#1144333).

  - cifs: clear PF_MEMALLOC before exiting demultiplex
    thread (bsc#1144333).

  - cifs: do not share tcons with DFS (bsc#1144333).

  - cifs: dump the session id and keys also for SMB2
    sessions (bsc#1144333).

  - cifs: ensure correct super block for DFS reconnect
    (bsc#1144333).

  - cifs: Fix bug which the return value by asynchronous
    read is error (bsc#1144333).

  - cifs: fix uninitialised lease_key in open_shroot()
    (bsc#1144333).

  - cifs: improve read performance for page size 64KB &
    cache=strict & vers=2.1+ (bsc#1144333).

  - cifs: Increment num_remote_opens stats counter even in
    case of smb2_query_dir_first (bsc#1144333).

  - cifs: minor update to comments around the
    cifs_tcp_ses_lock mutex (bsc#1144333).

  - cifs: protect updating server->dstaddr with a spinlock
    (bsc#1144333).

  - cifs: smb2pdu.h: Replace zero-length array with
    flexible-array member (bsc#1144333).

  - cifs: smbd: Calculate the correct maximum packet size
    for segmented SMBDirect send/receive (bsc#1144333).

  - cifs: smbd: Check and extend sender credits in interrupt
    context (bsc#1144333).

  - cifs: smbd: Check send queue size before posting a send
    (bsc#1144333).

  - cifs: smbd: Do not schedule work to send immediate
    packet on every receive (bsc#1144333).

  - cifs: smbd: Merge code to track pending packets
    (bsc#1144333).

  - cifs: smbd: Properly process errors on ib_post_send
    (bsc#1144333).

  - cifs: smbd: Update receive credits before sending and
    deal with credits roll back on failure before sending
    (bsc#1144333).

  - cifs: Warn less noisily on default mount (bsc#1144333).

  - clk: Add clk_hw_unregister_composite helper function
    definition (bsc#1051510).

  - clk: imx6ull: use OSC clock during AXI rate change
    (bsc#1051510).

  - clk: imx: make mux parent strings const (bsc#1051510).

  - clk: mediatek: correct the clocks for MT2701 HDMI PHY
    module (bsc#1051510).

  - clk: sunxi-ng: a64: Fix gate bit of DSI DPHY
    (bsc#1051510).

  - clocksource/drivers/hyper-v: Set TSC clocksource as
    default w/ InvariantTSC (bsc#1170620, bsc#1170621).

  - clocksource: dw_apb_timer_of: Fix missing clockevent
    timers (bsc#1051510).

  - component: Silence bind error on -EPROBE_DEFER
    (bsc#1051510).

  - coresight: do not use the BIT() macro in the UAPI header
    (git fixes (block drivers)).

  - cpufreq: s3c64xx: Remove pointless NULL check in
    s3c64xx_cpufreq_driver_init (bsc#1051510).

  - crypto: ccp - AES CFB mode is a stream cipher
    (git-fixes).

  - crypto: ccp - Clean up and exit correctly on allocation
    failure (git-fixes).

  - crypto: ccp - Cleanup misc_dev on sev_exit()
    (bsc#1114279).

  - crypto: ccp - Cleanup sp_dev_master in psp_dev_destroy()
    (bsc#1114279).

  - cxgb4: fix MPS index overwrite when setting MAC address
    (bsc#1127355).

  - cxgb4: fix Txq restart check during backpressure
    (bsc#1127354 bsc#1127371).

  - debugfs: Add debugfs_create_xul() for hexadecimal
    unsigned long (git-fixes).

  - debugfs_lookup(): switch to lookup_one_len_unlocked()
    (bsc#1171979).

  - devlink: fix return value after hitting end in region
    read (bsc#1109837).

  - devlink: validate length of param values (bsc#1109837).

  - devlink: validate length of region addr/len
    (bsc#1109837).

  - dmaengine: dmatest: Fix iteration non-stop logic
    (bsc#1051510).

  - dm mpath: switch paths in dm_blk_ioctl() code path
    (bsc#1167574).

  - dm-raid1: fix invalid return value from dm_mirror
    (bsc#1172378).

  - dm writecache: fix data corruption when reloading the
    target (git fixes (block drivers)).

  - dm writecache: fix incorrect flush sequence when doing
    SSD mode commit (git fixes (block drivers)).

  - dm writecache: verify watermark during resume (git fixes
    (block drivers)).

  - dm zoned: fix invalid memory access (git fixes (block
    drivers)).

  - dm zoned: reduce overhead of backing device checks (git
    fixes (block drivers)).

  - dm zoned: remove duplicate nr_rnd_zones increase in
    dmz_init_zone() (git fixes (block drivers)).

  - dm zoned: support zone sizes smaller than 128MiB (git
    fixes (block drivers)).

  - dp83640: reverse arguments to list_add_tail (git-fixes).

  - drivers: hv: Add a module description line to the
    hv_vmbus driver (bsc#1172249, bsc#1172251).

  - drivers/net/ibmvnic: Update VNIC protocol version
    reporting (bsc#1065729).

  - drivers: w1: add hwmon support structures
    (jsc#SLE-11048).

  - drivers: w1: add hwmon temp support for w1_therm
    (jsc#SLE-11048).

  - drivers: w1: refactor w1_slave_show to make the temp
    reading functionality separate (jsc#SLE-11048).

  - drm: amd/acp: fix broken menu structure (bsc#1114279)

  - drm/amdgpu: Correctly initialize thermal controller for
    GPUs with Powerplay table v0 (e.g Hawaii) (bsc#1111666).

  - drm/amdgpu: Fix oops when pp_funcs is unset in ACPI
    event (bsc#1111666).

  - drm/amd/powerplay: force the trim of the mclk dpm_levels
    if OD is (bsc#1113956)

  - drm/atomic: Take the atomic toys away from X
    (bsc#1112178) &#9;* context changes

  - drm/crc: Actually allow to change the crc source
    (bsc#1114279) &#9;* offset changes

  - drm/dp_mst: Fix clearing payload state on topology
    disable (bsc#1051510).

  - drm/dp_mst: Reformat drm_dp_check_act_status() a bit
    (bsc#1051510).

  - drm/edid: Fix off-by-one in DispID DTD pixel clock
    (bsc#1114279)

  - drm/etnaviv: fix perfmon domain interation (bsc#1113956)

  - drm/etnaviv: rework perfmon query infrastructure
    (bsc#1112178)

  - drm/i915: Apply Wa_1406680159:icl,ehl as an engine
    workaround (bsc#1112178)

  - drm/i915/gvt: Init DPLL/DDI vreg for virtual display
    instead of (bsc#1114279)

  - drm/i915: HDCP: fix Ri prime check done during link
    check (bsc#1112178)

  - drm/i915: properly sanity check batch_start_offset
    (bsc#1114279)

  - drm/meson: Delete an error message in
    meson_dw_hdmi_bind() (bsc#1051510).

  - drm: NULL pointer dereference [null-pointer-deref] (CWE
    476) problem (bsc#1114279)

  - drm/qxl: qxl_release leak in qxl_draw_dirty_fb()
    (bsc#1051510).

  - drm/qxl: qxl_release leak in qxl_hw_surface_alloc()
    (bsc#1051510).

  - drm/qxl: qxl_release use after free (bsc#1051510).

  - drm: Remove PageReserved manipulation from drm_pci_alloc
    (bsc#1114279)

  - drm/sun4i: dsi: Allow binding the host without a panel
    (bsc#1113956)

  - drm/sun4i: dsi: Avoid hotplug race with DRM driver bind
    (bsc#1113956)

  - drm/sun4i: dsi: Remove incorrect use of runtime PM
    (bsc#1113956)

  - drm/sun4i: dsi: Remove unused drv from driver context
    (bsc#1113956)

  - dump_stack: avoid the livelock of the dump_lock (git
    fixes (block drivers)).

  - EDAC, sb_edac: Add support for systems with segmented
    PCI buses (bsc#1169525).

  - ext4: do not zeroout extents beyond i_disksize
    (bsc#1167851).

  - ext4: fix extent_status fragmentation for plain files
    (bsc#1171949).

  - ext4: use non-movable memory for superblock readahead
    (bsc#1171952).

  - fanotify: fix merging marks masks with FAN_ONDIR
    (bsc#1171679).

  - fbcon: fix null-ptr-deref in fbcon_switch (bsc#1114279)

  - fib: add missing attribute validation for tun_id
    (networking-stable-20_03_14).

  - firmware: qcom: scm: fix compilation error when disabled
    (bsc#1051510).

  - Fix a backport bug, where btrfs_put_root() ->
    btrfs_put_fs_root() modification is not needed due to
    missing dependency

  - Following two patches needs to be combined as one commit
    (one adds context, later removes which affects existing
    patch) else commit series cannot be sequenced.

  - fpga: dfl: afu: Corrected error handling levels
    (git-fixes).

  - fs/cifs: fix gcc warning in sid_to_id (bsc#1144333).

  - fs/seq_file.c: simplify seq_file iteration code and
    interface (bsc#1170125).

  - gpio: tegra: mask GPIO IRQs during IRQ shutdown
    (bsc#1051510).

  - gre: fix uninit-value in __iptunnel_pull_header
    (networking-stable-20_03_14).

  - HID: hid-input: clear unmapped usages (git-fixes).

  - HID: hyperv: Add a module description line (bsc#1172249,
    bsc#1172251).

  - HID: i2c-hid: add Trekstor Primebook C11B to descriptor
    override (git-fixes).

  - HID: i2c-hid: override HID descriptors for certain
    devices (git-fixes).

  - HID: multitouch: add eGalaxTouch P80H84 support
    (bsc#1051510).

  - HID: wacom: Read HID_DG_CONTACTMAX directly for
    non-generic devices (git-fixes).

  - hrtimer: Annotate lockless access to timer->state (git
    fixes (block drivers)).

  - hsr: add restart routine into hsr_get_node_list()
    (networking-stable-20_03_28).

  - hsr: check protocol version in hsr_newlink()
    (networking-stable-20_04_17).

  - hsr: fix general protection fault in hsr_addr_is_self()
    (networking-stable-20_03_28).

  - hsr: set .netnsok flag (networking-stable-20_03_28).

  - hsr: use rcu_read_lock() in hsr_get_node_(list/status)()
    (networking-stable-20_03_28).

  - i2c: acpi: Force bus speed to 400KHz if a Silead
    touchscreen is present (git-fixes).

  - i2c: acpi: put device when verifying client fails
    (git-fixes).

  - i2c: brcmstb: remove unused struct member (git-fixes).

  - i2c: core: Allow empty id_table in ACPI case as well
    (git-fixes).

  - i2c: core: decrease reference count of device node in
    i2c_unregister_device (git-fixes).

  - i2c: dev: Fix the race between the release of i2c_dev
    and cdev (bsc#1051510).

  - i2c: fix missing pm_runtime_put_sync in i2c_device_probe
    (git-fixes).

  - i2c-hid: properly terminate
    i2c_hid_dmi_desc_override_table array (git-fixes).

  - i2c: i801: Do not add ICH_RES_IO_SMI for the iTCO_wdt
    device (git-fixes).

  - i2c: iproc: Stop advertising support of SMBUS quick cmd
    (git-fixes).

  - i2c: isch: Remove unnecessary acpi.h include
    (git-fixes).

  - i2c: mux: demux-pinctrl: Fix an error handling path in
    'i2c_demux_pinctrl_probe()' (bsc#1051510).

  - i2c: st: fix missing struct parameter description
    (bsc#1051510).

  - IB/mlx5: Fix missing congestion control debugfs on rep
    rdma device (bsc#1103991).

  - ibmvnic: Skip fatal error reset after passive init
    (bsc#1171078 ltc#184239).

  - iio:ad7797: Use correct attribute_group (bsc#1051510).

  - iio: adc: stm32-adc: fix device used to request dma
    (bsc#1051510).

  - iio: adc: stm32-adc: fix sleep in atomic context
    (git-fixes).

  - iio: adc: stm32-adc: Use dma_request_chan() instead
    dma_request_slave_channel() (bsc#1051510).

  - iio: dac: vf610: Fix an error handling path in
    'vf610_dac_probe()' (bsc#1051510).

  - iio: sca3000: Remove an erroneous 'get_device()'
    (bsc#1051510).

  - iio: xilinx-xadc: Fix ADC-B powerdown (bsc#1051510).

  - iio: xilinx-xadc: Fix clearing interrupt when enabling
    trigger (bsc#1051510).

  - iio: xilinx-xadc: Fix sequencer configuration for aux
    channels in simultaneous mode (bsc#1051510).

  - ima: Fix return value of ima_write_policy() (git-fixes).

  - input: evdev - call input_flush_device() on release(),
    not flush() (bsc#1051510).

  - input: hyperv-keyboard - add module description
    (bsc#1172249, bsc#1172251).

  - input: i8042 - add Acer Aspire 5738z to nomux list
    (bsc#1051510).

  - input: i8042 - add ThinkPad S230u to i8042 reset list
    (bsc#1051510).

  - input: raydium_i2c_ts - use true and false for boolean
    values (bsc#1051510).

  - input: synaptics-rmi4 - fix error return code in
    rmi_driver_probe() (bsc#1051510).

  - input: synaptics-rmi4 - really fix attn_data
    use-after-free (git-fixes).

  - input: usbtouchscreen - add support for BonXeon TP
    (bsc#1051510).

  - input: xpad - add custom init packet for Xbox One S
    controllers (bsc#1051510).

  - iommu/amd: Call domain_flush_complete() in
    update_domain() (bsc#1172096).

  - iommu/amd: Do not flush Device Table in iommu_map_page()
    (bsc#1172097).

  - iommu/amd: Do not loop forever when trying to increase
    address space (bsc#1172098).

  - iommu/amd: Fix legacy interrupt remapping for
    x2APIC-enabled system (bsc#1172099).

  - iommu/amd: Fix over-read of ACPI UID from IVRS table
    (bsc#1172101).

  - iommu/amd: Fix race in
    increase_address_space()/fetch_pte() (bsc#1172102).

  - iommu/amd: Update Device Table in
    increase_address_space() (bsc#1172103).

  - iommu: Fix reference count leak in iommu_group_alloc
    (bsc#1172397).

  - ip6_tunnel: Allow rcv/xmit even if remote address is a
    local address (bsc#1166978).

  - ipmi: fix hung processes in __get_guid() (git-fixes).

  - ipv4: fix a RCU-list lock in fib_triestat_seq_show
    (networking-stable-20_04_02).

  - ipv6/addrconf: call ipv6_mc_up() for non-Ethernet
    interface (networking-stable-20_03_14).

  - ipv6: do not auto-add link-local address to lag ports
    (networking-stable-20_04_09).

  - ipv6: fix IPV6_ADDRFORM operation logic (bsc#1171662).

  - ipv6: Fix nlmsg_flags when splitting a multipath route
    (networking-stable-20_03_01).

  - ipv6: fix restrict IPV6_ADDRFORM operation
    (bsc#1171662).

  - ipv6: Fix route replacement with dev-only route
    (networking-stable-20_03_01).

  - ipvlan: add cond_resched_rcu() while processing muticast
    backlog (networking-stable-20_03_14).

  - ipvlan: do not deref eth hdr before checking it's set
    (networking-stable-20_03_14).

  - ipvlan: do not use cond_resched_rcu() in
    ipvlan_process_multicast() (networking-stable-20_03_14).

  - iwlwifi: pcie: actually release queue memory in TVQM
    (bsc#1051510).

  - ixgbe: do not check firmware errors (bsc#1170284).

  - kABI fix for early XHCI debug (git-fixes).

  - kabi for for md: improve handling of bio with
    REQ_PREFLUSH in md_flush_request() (git-fixes).

  - kabi/severities: Do not track KVM internal symbols.

  - kabi/severities: Ingnore get_dev_data() The function is
    internal to the AMD IOMMU driver and must not be called
    by any third-party.

  - kABI workaround for snd_rawmidi buffer_ref field
    addition (git-fixes).

  - keys: reaching the keys quotas correctly (bsc#1051510).

  - KVM: arm64: Change hyp_panic()s dependency on tpidr_el2
    (bsc#1133021).

  - KVM: arm64: Stop save/restoring host tpidr_el1 on VHE
    (bsc#1133021).

  - KVM: Check validity of resolved slot when searching
    memslots (bsc#1172104).

  - KVM: s390: vsie: Fix delivery of addressing exceptions
    (git-fixes).

  - KVM: s390: vsie: Fix possible race when shadowing region
    3 tables (git-fixes).

  - KVM: s390: vsie: Fix region 1 ASCE sanity shadow address
    checks (git-fixes).

  - KVM: SVM: Fix potential memory leak in svm_cpu_init()
    (bsc#1171736).

  - KVM x86: Extend AMD specific guest behavior to Hygon
    virtual CPUs (bsc#1152489).

  - l2tp: Allow management of tunnels and session in user
    namespace (networking-stable-20_04_17).

  - libata: Remove extra scsi_host_put() in
    ata_scsi_add_hosts() (bsc#1051510).

  - libata: Return correct status in
    sata_pmp_eh_recover_pm() when ATA_DFLAG_DETACH is set
    (bsc#1051510).

  - lib: raid6: fix awk build warnings (git fixes (block
    drivers)).

  - lib/raid6/test: fix build on distros whose /bin/sh is
    not bash (git fixes (block drivers)).

  - lib/stackdepot.c: fix global out-of-bounds in
    stack_slabs (git fixes (block drivers)).

  - locks: print unsigned ino in /proc/locks (bsc#1171951).

  - mac80211: add ieee80211_is_any_nullfunc() (bsc#1051510).

  - mac80211_hwsim: Use kstrndup() in place of kasprintf()
    (bsc#1051510).

  - mac80211: mesh: fix discovery timer re-arming issue /
    crash (bsc#1051510).

  - macsec: avoid to set wrong mtu (bsc#1051510).

  - macsec: restrict to ethernet devices
    (networking-stable-20_03_28).

  - macvlan: add cond_resched() during multicast processing
    (networking-stable-20_03_14).

  - macvlan: fix null dereference in macvlan_device_event()
    (bsc#1051510).

  - md: improve handling of bio with REQ_PREFLUSH in
    md_flush_request() (git-fixes).

  - md/raid0: Fix an error message in raid0_make_request()
    (git fixes (block drivers)).

  - md/raid10: prevent access of uninitialized resync_pages
    offset (git-fixes).

  - media: dvb: return -EREMOTEIO on i2c transfer failure
    (bsc#1051510).

  - media: platform: fcp: Set appropriate DMA parameters
    (bsc#1051510).

  - media: ti-vpe: cal: fix disable_irqs to only the
    intended target (git-fixes).

  - mei: release me_cl object reference (bsc#1051510).

  - mlxsw: Fix some IS_ERR() vs NULL bugs
    (networking-stable-20_04_27).

  - mlxsw: spectrum_flower: Do not stop at
    FLOW_ACTION_VLAN_MANGLE (networking-stable-20_04_09).

  - mlxsw: spectrum_mr: Fix list iteration in error path
    (bsc#1112374).

  - mmc: atmel-mci: Fix debugfs on 64-bit platforms
    (git-fixes).

  - mmc: core: Check request type before completing the
    request (git-fixes).

  - mmc: core: Fix recursive locking issue in CQE recovery
    path (git-fixes).

  - mmc: cqhci: Avoid false 'cqhci: CQE stuck on' by not
    open-coding timeout loop (git-fixes).

  - mmc: dw_mmc: Fix debugfs on 64-bit platforms
    (git-fixes).

  - mmc: meson-gx: make sure the descriptor is stopped on
    errors (git-fixes).

  - mmc: meson-gx: simplify interrupt handler (git-fixes).

  - mmc: renesas_sdhi: limit block count to 16 bit for old
    revisions (git-fixes).

  - mmc: sdhci-esdhc-imx: fix the mask for tuning start
    point (bsc#1051510).

  - mmc: sdhci-msm: Clear tuning done flag while hs400
    tuning (bsc#1051510).

  - mmc: sdhci-of-at91: fix memleak on clk_get failure
    (git-fixes).

  - mmc: sdhci-pci: Fix eMMC driver strength for BYT-based
    controllers (bsc#1051510).

  - mmc: sdhci: Update the tuning failed messages to
    pr_debug level (git-fixes).

  - mmc: sdhci-xenon: fix annoying 1.8V regulator warning
    (bsc#1051510).

  - mmc: sdio: Fix potential NULL pointer error in
    mmc_sdio_init_card() (bsc#1051510).

  - mmc: tmio: fix access width of Block Count Register
    (git-fixes).

  - mm: limit boost_watermark on small zones (git fixes
    (mm/pgalloc)).

  - mm: thp: handle page cache THP correctly in
    PageTransCompoundMap (git fixes (block drivers)).

  - mtd: cfi: fix deadloop in cfi_cmdset_0002.c
    do_write_buffer (bsc#1051510).

  - mtd: spi-nor: cadence-quadspi: add a delay in write
    sequence (git-fixes).

  - mtd: spi-nor: enable 4B opcodes for mx66l51235l
    (git-fixes).

  - mtd: spi-nor: fsl-quadspi: Do not let -EINVAL on the bus
    (git-fixes).

  - mwifiex: avoid -Wstringop-overflow warning
    (bsc#1051510).

  - mwifiex: Fix memory corruption in dump_station
    (bsc#1051510).

  - net: bcmgenet: correct per TX/RX ring statistics
    (networking-stable-20_04_27).

  - net: dsa: b53: Fix ARL register definitions
    (networking-stable-20_04_27).

  - net: dsa: b53: Rework ARL bin logic
    (networking-stable-20_04_27).

  - net: dsa: bcm_sf2: Do not register slave MDIO bus with
    OF (networking-stable-20_04_09).

  - net: dsa: bcm_sf2: Ensure correct sub-node is parsed
    (networking-stable-20_04_09).

  - net: dsa: bcm_sf2: Fix overflow checks (git-fixes).

  - net: dsa: Fix duplicate frames flooded by learning
    (networking-stable-20_03_28).

  - net: dsa: mv88e6xxx: fix lockup on warm boot
    (networking-stable-20_03_14).

  - net/ethernet: add Google GVE driver (jsc#SLE-10538)

  - net: fec: add phy_reset_after_clk_enable() support
    (git-fixes).

  - net: fec: validate the new settings in
    fec_enet_set_coalesce() (networking-stable-20_03_14).

  - net: fib_rules: Correctly set table field when table
    number exceeds 8 bits (networking-stable-20_03_01).

  - net: fix race condition in __inet_lookup_established()
    (bsc#1151794).

  - net: fq: add missing attribute validation for orphan
    mask (networking-stable-20_03_14).

  - net: hns3: fix 'tc qdisc del' failed issue
    (bsc#1109837).

  - net, ip_tunnel: fix interface lookup with no key
    (networking-stable-20_04_02).

  - net: ipv4: devinet: Fix crash when add/del multicast IP
    with autojoin (networking-stable-20_04_17).

  - net: ipv6: do not consider routes via gateways for
    anycast address check (networking-stable-20_04_17).

  - netlink: Use netlink header as base to calculate bad
    attribute offset (networking-stable-20_03_14).

  - net: macsec: update SCI upon MAC address change
    (networking-stable-20_03_14).

  - net: memcg: fix lockdep splat in inet_csk_accept()
    (networking-stable-20_03_14).

  - net: memcg: late association of sock to memcg
    (networking-stable-20_03_14).

  - net/mlx4_en: avoid indirect call in TX completion
    (networking-stable-20_04_27).

  - net/mlx5: Add new fields to Port Type and Speed register
    (bsc#1171118).

  - net/mlx5: Expose link speed directly (bsc#1171118).

  - net/mlx5: Expose port speed when possible (bsc#1171118).

  - net/mlx5: Fix failing fw tracer allocation on s390
    (bsc#1103990 ).

  - net: mvneta: Fix the case where the last poll did not
    process all rx (networking-stable-20_03_28).

  - net: netrom: Fix potential nr_neigh refcnt leak in
    nr_add_node (networking-stable-20_04_27).

  - net/packet: tpacket_rcv: do not increment ring index on
    drop (networking-stable-20_03_14).

  - net: phy: restore mdio regs in the iproc mdio driver
    (networking-stable-20_03_01).

  - net: qmi_wwan: add support for ASKEY WWHC050
    (networking-stable-20_03_28).

  - net: revert default NAPI poll timeout to 2 jiffies
    (networking-stable-20_04_17).

  - net_sched: cls_route: remove the right filter from
    hashtable (networking-stable-20_03_28).

  - net_sched: sch_skbprio: add message validation to
    skbprio_change() (bsc#1109837).

  - net/x25: Fix x25_neigh refcnt leak when receiving frame
    (networking-stable-20_04_27).

  - nfc: add missing attribute validation for SE API
    (networking-stable-20_03_14).

  - nfc: add missing attribute validation for vendor
    subcommand (networking-stable-20_03_14).

  - nfc: pn544: Fix occasional HW initialization failure
    (networking-stable-20_03_01).

  - NFC: st21nfca: add missed kfree_skb() in an error path
    (bsc#1051510).

  - nfp: abm: fix a memory leak bug (bsc#1109837).

  - nfsd4: fix up replay_matches_cache() (git-fixes).

  - nfsd: Ensure CLONE persists data and metadata changes to
    the target file (git-fixes).

  - nfsd: fix delay timer on 32-bit architectures
    (git-fixes).

  - nfsd: fix jiffies/time_t mixup in LRU list (git-fixes).

  - nfs: Directory page cache pages need to be locked when
    read (git-fixes).

  - nfsd: memory corruption in nfsd4_lock() (git-fixes).

  - nfs: Do not call generic_error_remove_page() while
    holding locks (bsc#1170457).

  - nfs: Fix memory leaks and corruption in readdir
    (git-fixes).

  - nfs: Fix O_DIRECT accounting of number of bytes
    read/written (git-fixes).

  - nfs: Fix potential posix_acl refcnt leak in nfs3_set_acl
    (git-fixes).

  - nfs: fix racey wait in nfs_set_open_stateid_locked
    (bsc#1170592).

  - NFS/flexfiles: Use the correct TCP timeout for flexfiles
    I/O (git-fixes).

  - NFS/pnfs: Fix pnfs_generic_prepare_to_resend_writes()
    (git-fixes).

  - nfs: Revalidate the file size on a fatal write error
    (git-fixes).

  - NFSv4.0: nfs4_do_fsinfo() should not do implicit lease
    renewals (git-fixes).

  - NFSv4: Do not allow a cached open with a revoked
    delegation (git-fixes).

  - NFSv4: Fix leak of clp->cl_acceptor string (git-fixes).

  - NFSv4-Fix-OPEN-CLOSE-race.patch

  - NFSv4/pnfs: Return valid stateids in
    nfs_layout_find_inode_by_stateid() (git-fixes).

  - NFSv4: try lease recovery on NFS4ERR_EXPIRED
    (git-fixes).

  - NFSv4.x: Drop the slot if nfs4_delegreturn_prepare waits
    for layoutreturn (git-fixes).

  - nl802154: add missing attribute validation for dev_type
    (networking-stable-20_03_14).

  - nl802154: add missing attribute validation
    (networking-stable-20_03_14).

  - nvme-fc: print proper nvme-fc devloss_tmo value
    (bsc#1172391).

  - objtool: Fix stack offset tracking for indirect CFAs
    (bsc#1169514).

  - objtool: Fix switch table detection in .text.unlikely
    (bsc#1169514).

  - objtool: Make BP scratch register warning more robust
    (bsc#1169514).

  - padata: Remove broken queue flushing (git-fixes).

  - Partially revert 'kfifo: fix kfifo_alloc() and
    kfifo_init()' (git fixes (block drivers)).

  - PCI: hv: Add support for protocol 1.3 and support
    PCI_BUS_RELATIONS2 (bsc#1172201, bsc#1172202).

  - PCI: hv: Decouple the func definition in hv_dr_state
    from VSP message (bsc#1172201, bsc#1172202).

  - PCI/PM: Call .bridge_d3() hook only if non-NULL
    (git-fixes).

  - perf: Allocate context task_ctx_data for child event
    (git-fixes).

  - perf/cgroup: Fix perf cgroup hierarchy support
    (git-fixes).

  - perf: Copy parent's address filter offsets on clone
    (git-fixes).

  - perf/core: Add sanity check to deal with pinned event
    failure (git-fixes).

  - perf/core: Avoid freeing static PMU contexts when PMU is
    unregistered (git-fixes).

  - perf/core: Correct event creation with PERF_FORMAT_GROUP
    (git-fixes).

  - perf/core: Do not WARN() for impossible ring-buffer
    sizes (git-fixes).

  - perf/core: Fix ctx_event_type in ctx_resched()
    (git-fixes).

  - perf/core: Fix error handling in perf_event_alloc()
    (git-fixes).

  - perf/core: Fix exclusive events' grouping (git-fixes).

  - perf/core: Fix group scheduling with mixed hw and sw
    events (git-fixes).

  - perf/core: Fix impossible ring-buffer sizes warning
    (git-fixes).

  - perf/core: Fix locking for children siblings group read
    (git-fixes).

  - perf/core: Fix lock inversion between perf,trace,cpuhp
    (git-fixes (dependent patch for 18736eef1213)).

  - perf/core: Fix perf_event_read_value() locking
    (git-fixes).

  - perf/core: Fix perf_pmu_unregister() locking
    (git-fixes).

  - perf/core: Fix __perf_read_group_add() locking
    (git-fixes (dependent patch)).

  - perf/core: Fix perf_sample_regs_user() mm check
    (git-fixes).

  - perf/core: Fix possible Spectre-v1 indexing for
    ->aux_pages (git-fixes).

  - perf/core: Fix race between close() and fork()
    (git-fixes).

  - perf/core: Fix the address filtering fix (git-fixes).

  - perf/core: Fix use-after-free in uprobe_perf_close()
    (git-fixes).

  - perf/core: Force USER_DS when recording user stack data
    (git-fixes).

  - perf/core: Restore mmap record type correctly
    (git-fixes).

  - perf: Fix header.size for namespace events (git-fixes).

  - perf/ioctl: Add check for the sample_period value
    (git-fixes).

  - perf, pt, coresight: Fix address filters for vmas with
    non-zero offset (git-fixes).

  - perf: Return proper values for user stack errors
    (git-fixes).

  - pinctrl: baytrail: Enable pin configuration setting for
    GPIO chip (git-fixes).

  - pinctrl: cherryview: Add missing spinlock usage in
    chv_gpio_irq_handler (git-fixes).

  - pinctrl: sunrisepoint: Fix PAD lock register offset for
    SPT-H (git-fixes).

  - platform/x86: asus-nb-wmi: Do not load on Asus T100TA
    and T200TA (bsc#1051510).

  - pnfs: Ensure we do clear the return-on-close layout
    stateid on fatal errors (git-fixes).

  - powerpc: Add attributes for setjmp/longjmp
    (bsc#1065729).

  - powerpc/pci/of: Parse unassigned resources
    (bsc#1065729).

  - powerpc/setup_64: Set cache-line-size based on
    cache-block-size (bsc#1065729).

  - powerpc/sstep: Fix DS operand in ld encoding to
    appropriate value (bsc#1065729).

  - qede: Fix race between rdma destroy workqueue and link
    change event (networking-stable-20_03_01).

  - r8152: check disconnect status after long sleep
    (networking-stable-20_03_14).

  - raid6/ppc: Fix build for clang (git fixes (block
    drivers)).

  - random: always use batched entropy for
    get_random_u(32,64) (bsc#1164871).

  - rcu: locking and unlocking need to always be at least
    barriers (git fixes (block drivers)).

  - Redo patch for SLE15-SP1, based on feedback from IBM:
    patches.suse/s390-ftrace-fix-potential-crashes-when-swit
    ching-tracers (bsc#1171244 LTC#185785 git-fixes).

  - resolve KABI warning for perf-pt-coresight (git-fixes).

  - Revert 'ALSA: hda/realtek: Fix pop noise on ALC225'
    (git-fixes).

  - Revert 'drm/panel: simple: Add support for Sharp
    LQ150X1LG11 panels' (bsc#1114279) &#9;* offset changes

  - Revert 'HID: i2c-hid: add Trekstor Primebook C11B to
    descriptor override' Depends on
    9b5c747685982d22efffeafc5ec601bd28f6d78b, which was also
    reverted.

  - Revert 'HID: i2c-hid: override HID descriptors for
    certain devices' This broke i2c-hid.ko's build, there is
    no way around it without a big file rename or renaming
    the kernel module.

  - Revert 'i2c-hid: properly terminate
    i2c_hid_dmi_desc_override_table' Fixed
    9b5c747685982d22efffeafc5ec601bd28f6d78b, which was also
    reverted.

  - Revert 'ipc,sem: remove uneeded sem_undo_list lock usage
    in exit_sem()' (bsc#1172221).

  - Revert 'RDMA/cma: Simplify rdma_resolve_addr() error
    flow' (bsc#1103992).

  - rtlwifi: Fix a double free in _rtl_usb_tx_urb_setup()
    (bsc#1051510).

  - s390/cio: avoid duplicated 'ADD' uevents (git-fixes).

  - s390/cio: generate delayed uevent for vfio-ccw
    subchannels (git-fixes).

  - s390/cpuinfo: fix wrong output when CPU0 is offline
    (git-fixes).

  - s390/cpum_cf: Add new extended counters for IBM z15
    (bsc#1169762 LTC#185291).

  - s390/diag: fix display of diagnose call statistics
    (git-fixes).

  - s390/ftrace: fix potential crashes when switching
    tracers (git-fixes).

  - s390/gmap: return proper error code on ksm unsharing
    (git-fixes).

  - s390/ism: fix error return code in ism_probe()
    (git-fixes).

  - s390/pci: do not set affinity for floating irqs
    (git-fixes).

  - s390/pci: Fix possible deadlock in recover_store()
    (bsc#1165183 LTC#184103).

  - s390/pci: Recover handle in clp_set_pci_fn()
    (bsc#1165183 LTC#184103).

  - s390/qeth: cancel RX reclaim work earlier (git-fixes).

  - s390/qeth: do not return -ENOTSUPP to userspace
    (git-fixes).

  - s390/qeth: do not warn for napi with 0 budget
    (git-fixes).

  - s390/qeth: fix off-by-one in RX copybreak check
    (git-fixes).

  - s390/qeth: fix promiscuous mode after reset (git-fixes).

  - s390/qeth: fix qdio teardown after early init error
    (git-fixes).

  - s390/qeth: handle error due to unsupported transport
    mode (git-fixes).

  - s390/qeth: handle error when backing RX buffer
    (git-fixes).

  - s390/qeth: lock the card while changing its hsuid
    (git-fixes).

  - s390/qeth: support net namespaces for L3 devices
    (git-fixes).

  - s390/time: Fix clk type in get_tod_clock (git-fixes).

  - scripts/decodecode: fix trapping instruction formatting
    (bsc#1065729).

  - scripts/dtc: Remove redundant YYLOC global declaration
    (bsc#1160388).

  - scsi: bnx2i: fix potential use after free (bsc#1171600).

  - scsi: core: Handle drivers which set sg_tablesize to
    zero (bsc#1171601)

  - scsi: core: save/restore command resid for error
    handling (bsc#1171602).

  - scsi: core: scsi_trace: Use get_unaligned_be*()
    (bsc#1171604).

  - scsi: core: try to get module before removing device
    (bsc#1171605).

  - scsi: csiostor: Adjust indentation in csio_device_reset
    (bsc#1171606).

  - scsi: csiostor: Do not enable IRQs too early
    (bsc#1171607).

  - scsi: esas2r: unlock on error in
    esas2r_nvram_read_direct() (bsc#1171608).

  - scsi: fnic: fix invalid stack access (bsc#1171609).

  - scsi: fnic: fix msix interrupt allocation (bsc#1171610).

  -
    scsi-ibmvfc-Don-t-send-implicit-logouts-prior-to-NPI.pat
    ch

  - scsi: ibmvscsi: Fix WARN_ON during event pool release
    (bsc#1170791 ltc#185128).

  -
    scsi-ibmvscsi-Fix-WARN_ON-during-event-pool-release.patc
    h

  - scsi: iscsi: Avoid potential deadlock in iscsi_if_rx
    func (bsc#1171611).

  - scsi: iscsi: Fix a potential deadlock in the timeout
    handler (bsc#1171612).

  - scsi: iscsi: qla4xxx: fix double free in probe
    (bsc#1171613).

  - scsi: lpfc: Change default queue allocation for reduced
    memory consumption (bsc#1164780).

  - scsi: lpfc: fix: Coverity: lpfc_cmpl_els_rsp(): NULL
    pointer dereferences (bsc#1171614).

  - scsi: lpfc: Fix crash in target side cable pulls hitting
    WAIT_FOR_UNREG (bsc#1171615).

  - scsi: lpfc: Fix lpfc_nodelist leak when processing
    unsolicited event (bsc#1164780).

  - scsi: lpfc: Fix MDS Diagnostic Enablement definition
    (bsc#1164780).

  - scsi: lpfc: Fix negation of else clause in
    lpfc_prep_node_fc4type (bsc#1164780).

  - scsi: lpfc: Fix noderef and address space warnings
    (bsc#1164780).

  - scsi: lpfc: Maintain atomic consistency of queue_claimed
    flag (bsc#1164780).

  - scsi: lpfc: remove duplicate unloading checks
    (bsc#1164780).

  - scsi: lpfc: Remove re-binding of nvme rport during
    registration (bsc#1164780).

  - scsi: lpfc: Remove redundant initialization to variable
    rc (bsc#1164780).

  - scsi: lpfc: Remove unnecessary lockdep_assert_held calls
    (bsc#1164780).

  - scsi: lpfc: Update lpfc version to 12.8.0.1
    (bsc#1164780).

  - scsi: megaraid_sas: Do not initiate OCR if controller is
    not in ready state (bsc#1171616).

  - scsi: qla2xxx: add ring buffer for tracing debug logs
    (bsc#1157169).

  -
    scsi-qla2xxx-check-UNLOADING-before-posting-async-wo.pat
    ch

  - scsi: qla2xxx: check UNLOADING before posting async work
    (bsc#1157169).

  - scsi: qla2xxx: Delete all sessions before unregister
    local nvme port (bsc#1157169).

  - scsi: qla2xxx: Do not log message when reading port
    speed via sysfs (bsc#1157169).

  - scsi: qla2xxx: Fix hang when issuing nvme disconnect-all
    in NPIV (bsc#1157169).

  - scsi: qla2xxx: Fix regression warnings (bsc#1157169).

  - scsi: qla2xxx: Remove non functional code (bsc#1157169).

  - scsi: qla2xxx: set UNLOADING before waiting for session
    deletion (bsc#1157169).

  -
    scsi-qla2xxx-set-UNLOADING-before-waiting-for-sessio.pat
    ch

  - scsi: qla4xxx: Adjust indentation in qla4xxx_mem_free
    (bsc#1171617).

  - scsi: qla4xxx: fix double free bug (bsc#1171618).

  - scsi: sd: Clear sdkp->protection_type if disk is
    reformatted without PI (bsc#1171619).

  - scsi: sg: add sg_remove_request in sg_common_write
    (bsc#1171620).

  - scsi: tracing: Fix handling of TRANSFER LENGTH == 0 for
    READ(6) and WRITE(6) (bsc#1171621).

  - scsi: ufs: change msleep to usleep_range (bsc#1171622).

  - scsi: ufs: Clean up ufshcd_scale_clks() and clock
    scaling error out path (bsc#1171623).

  - scsi: ufs: Fix ufshcd_hold() caused scheduling while
    atomic (bsc#1171624).

  - scsi: ufs: Fix ufshcd_probe_hba() reture value in case
    ufshcd_scsi_add_wlus() fails (bsc#1171625).

  - scsi: ufs: Recheck bkops level if bkops is disabled
    (bsc#1171626).

  - scsi: zfcp: fix missing erp_lock in port recovery
    trigger for point-to-point (git-fixes).

  - sctp: fix possibly using a bad saddr with a given dst
    (networking-stable-20_04_02).

  - sctp: fix refcount bug in sctp_wfree
    (networking-stable-20_04_02).

  - sctp: move the format error check out of
    __sctp_sf_do_9_1_abort (networking-stable-20_03_01).

  - selftests/powerpc: Fix build errors in powerpc ptrace
    selftests (boo#1124278).

  - seq_file: fix problem when seeking mid-record
    (bsc#1170125).

  - serial: uartps: Move the spinlock after the read of the
    tx empty (git-fixes).

  - sfc: detach from cb_page in efx_copy_channel()
    (networking-stable-20_03_14).

  - signal/pid_namespace: Fix reboot_pid_ns to use send_sig
    not force_sig (bsc#1172185).

  - slcan: not call free_netdev before rtnl_unlock in
    slcan_open (networking-stable-20_03_28).

  - slip: make slhc_compress() more robust against malicious
    packets (networking-stable-20_03_14).

  - smb3: Additional compression structures (bsc#1144333).

  - smb3: Add new compression flags (bsc#1144333).

  - smb3: change noisy error message to FYI (bsc#1144333).

  - smb3: enable swap on SMB3 mounts (bsc#1144333).

  - smb3-fix-performance-regression-with-setting-mtime.patch

  - smb3: Minor cleanup of protocol definitions
    (bsc#1144333).

  - smb3: remove overly noisy debug line in signing errors
    (bsc#1144333).

  - smb3: smbdirect support can be configured by default
    (bsc#1144333).

  - smb3: use SMB2_SIGNATURE_SIZE define (bsc#1144333).

  - spi: bcm2835: Fix 3-wire mode if DMA is enabled
    (git-fixes).

  - spi: bcm63xx-hsspi: Really keep pll clk enabled
    (bsc#1051510).

  - spi: bcm-qspi: when tx/rx buffer is NULL set to 0
    (bsc#1051510).

  - spi: dw: Add SPI Rx-done wait method to DMA-based
    transfer (bsc#1051510).

  - spi: dw: Add SPI Tx-done wait method to DMA-based
    transfer (bsc#1051510).

  - spi: dw: Zero DMA Tx and Rx configurations on stack
    (bsc#1051510).

  - spi: fsl: do not map irq during probe (git-fixes).

  - spi: fsl: use platform_get_irq() instead of
    of_irq_to_resource() (git-fixes).

  - spi: pxa2xx: Add CS control clock quirk (bsc#1051510).

  - spi: qup: call spi_qup_pm_resume_runtime before
    suspending (bsc#1051510).

  - spi: spi-fsl-dspi: Replace interruptible wait queue with
    a simple completion (git-fixes).

  - spi: spi-s3c64xx: Fix system resume support (git-fixes).

  - spi/zynqmp: remove entry that causes a cs glitch
    (bsc#1051510).

  - staging: comedi: dt2815: fix writing hi byte of analog
    output (bsc#1051510).

  - staging: comedi: Fix comedi_device refcnt leak in
    comedi_open (bsc#1051510).

  - staging: iio: ad2s1210: Fix SPI reading (bsc#1051510).

  - staging: vt6656: Do not set RCR_MULTICAST or
    RCR_BROADCAST by default (git-fixes).

  - staging: vt6656: Fix drivers TBTT timing counter
    (git-fixes).

  - staging: vt6656: Fix pairwise key entry save
    (git-fixes).

  - sunrpc: expiry_time should be seconds not timeval
    (git-fixes).

  - sunrpc: Fix a potential buffer overflow in
    'svc_print_xprts()' (git-fixes).

  - supported.conf: Add br_netfilter to base (bsc#1169020).

  - supported.conf: support w1 core and thermometer support

  - svcrdma: Fix double svc_rdma_send_ctxt_put() in an error
    path (bsc#1103992).

  - svcrdma: Fix leak of transport addresses (git-fixes).

  - svcrdma: Fix trace point use-after-free race
    (bsc#1103992 ).

  - taskstats: fix data-race (bsc#1172188).

  - tcp: cache line align MAX_TCP_HEADER
    (networking-stable-20_04_27).

  - tcp: repair: fix TCP_QUEUE_SEQ implementation
    (networking-stable-20_03_28).

  - team: add missing attribute validation for array index
    (networking-stable-20_03_14).

  - team: add missing attribute validation for port ifindex
    (networking-stable-20_03_14).

  - team: fix hang in team_mode_get()
    (networking-stable-20_04_27).

  - tools lib traceevent: Remove unneeded qsort and uses
    memmove instead (git-fixes).

  - tpm: ibmvtpm: retry on H_CLOSED in tpm_ibmvtpm_send()
    (bsc#1065729).

  - tpm/tpm_tis: Free IRQ if probing fails (bsc#1082555).

  - tpm/tpm_tis: Free IRQ if probing fails (git-fixes).

  - tracing: Add a vmalloc_sync_mappings() for safe measure
    (git-fixes).

  - tracing: Disable trace_printk() on post poned tests
    (git-fixes).

  - tracing: Fix the race between registering 'snapshot'
    event trigger and triggering 'snapshot' operation
    (git-fixes).

  - tty: rocket, avoid OOB access (git-fixes).

  - tun: Do not put_page() for all negative return values
    from XDP program (bsc#1109837).

  - UAS: fix deadlock in error handling and PM flushing work
    (git-fixes).

  - UAS: no use logging any details in case of ENODEV
    (git-fixes).

  - Update config files: Build w1 bus on arm64
    (jsc#SLE-11048)

  - Update config files: re-enable CONFIG_HAMRADIO and co
    (bsc#1170740)

  - Update
    patches.suse/powerpc-pseries-ddw-Extend-upper-limit-for-
    huge-DMA-.patch (bsc#1142685 bsc#1167867 ltc#179509
    ltc#184616).

  - Update patches.suse/x86-mm-split-vmalloc_sync_all.patch
    (bsc#1165741, bsc#1166969).

  - Update references:
    patches.suse/s390-pci-do-not-set-affinity-for-floating-i
    rqs (bsc#1171817 LTC#185819 git-fixes).

  - usb: Add USB_QUIRK_DELAY_CTRL_MSG and
    USB_QUIRK_DELAY_INIT for Corsair K70 RGB RAPIDFIRE
    (git-fixes).

  - usb: cdc-acm: restore capability check order
    (git-fixes).

  - usb: core: Fix misleading driver bug report
    (bsc#1051510).

  - usb: dwc3: do not set gadget->is_otg flag (git-fixes).

  - usb: dwc3: gadget: Do link recovery for SS and SSP
    (git-fixes).

  - usb: early: Handle AMD's spec-compliant identifiers, too
    (git-fixes).

  - usb: f_fs: Clear OS Extended descriptor counts to zero
    in ffs_data_reset() (git-fixes).

  - usb: gadget: audio: Fix a missing error return value in
    audio_bind() (git-fixes).

  - usb: gadget: composite: Inform controller driver of
    self-powered (git-fixes).

  - usb: gadget: legacy: fix error return code in cdc_bind()
    (git-fixes).

  - usb: gadget: legacy: fix error return code in
    gncm_bind() (git-fixes).

  - usb: gadget: legacy: fix redundant initialization
    warnings (bsc#1051510).

  - usb: gadget: net2272: Fix a memory leak in an error
    handling path in 'net2272_plat_probe()' (git-fixes).

  - usb: gadget: udc: atmel: Fix vbus disconnect handling
    (git-fixes).

  - usb: gadget: udc: atmel: Make some symbols static
    (git-fixes).

  - usb: gadget: udc: bdc: Remove unnecessary NULL checks in
    bdc_req_complete (git-fixes).

  - usb: host: xhci-plat: keep runtime active when removing
    host (git-fixes).

  - usb: hub: Fix handling of connect changes during sleep
    (git-fixes).

  - usbnet: silence an unnecessary warning (bsc#1170770).

  - usb: serial: garmin_gps: add sanity checking for data
    length (git-fixes).

  - usb: serial: option: add BroadMobi BM806U (git-fixes).

  - usb: serial: option: add support for ASKEY WWHC050
    (git-fixes).

  - usb: serial: option: add Wistron Neweb D19Q1
    (git-fixes).

  - usb: serial: qcserial: Add DW5816e support (git-fixes).

  - usb: sisusbvga: Change port variable from signed to
    unsigned (git-fixes).

  - usb-storage: Add unusual_devs entry for JMicron JMS566
    (git-fixes).

  - usb: uas: add quirk for LaCie 2Big Quadra (git-fixes).

  - usb: xhci: Fix NULL pointer dereference when enqueuing
    trbs from urb sg list (git-fixes).

  - video: fbdev: sis: Remove unnecessary parentheses and
    commented code (bsc#1114279)

  - video: fbdev: w100fb: Fix a potential double free
    (bsc#1051510).

  - vrf: Check skb for XFRM_TRANSFORMED flag
    (networking-stable-20_04_27).

  - vt: ioctl, switch VT_IS_IN_USE and VT_BUSY to inlines
    (git-fixes).

  - vt: selection, introduce vc_is_sel (git-fixes).

  - vt: vt_ioctl: fix race in VT_RESIZEX (git-fixes).

  - vt: vt_ioctl: fix use-after-free in vt_in_use()
    (git-fixes).

  - vt: vt_ioctl: fix VT_DISALLOCATE freeing in-use virtual
    console (git-fixes).

  - vxlan: check return value of gro_cells_init()
    (networking-stable-20_03_28).

  - w1: Add subsystem kernel public interface
    (jsc#SLE-11048).

  - w1: Fix slave count on 1-Wire bus (resend)
    (jsc#SLE-11048).

  - w1: keep balance of mutex locks and refcnts
    (jsc#SLE-11048).

  - w1: use put_device() if device_register() fail
    (jsc#SLE-11048).

  - watchdog: reset last_hw_keepalive time at start
    (git-fixes).

  - wcn36xx: Fix error handling path in 'wcn36xx_probe()'
    (bsc#1051510).

  - wil6210: remove reset file from debugfs (git-fixes).

  - wimax/i2400m: Fix potential urb refcnt leak
    (bsc#1051510).

  - workqueue: do not use wq_select_unbound_cpu() for bound
    works (bsc#1172130).

  - x86/entry/64: Fix unwind hints in kernel exit path
    (bsc#1058115).

  - x86/entry/64: Fix unwind hints in register clearing code
    (bsc#1058115).

  - x86/entry/64: Fix unwind hints in rewind_stack_do_exit()
    (bsc#1058115).

  - x86/entry/64: Fix unwind hints in __switch_to_asm()
    (bsc#1058115).

  - x86/hyperv: Allow guests to enable InvariantTSC
    (bsc#1170621, bsc#1170620).

  - x86/Hyper-V: Free hv_panic_page when fail to register
    kmsg dump (bsc#1170617, bsc#1170618).

  - x86/Hyper-V: Report crash data in die() when
    panic_on_oops is set (bsc#1170617, bsc#1170618).

  - x86/Hyper-V: Report crash register data or kmsg before
    running crash kernel (bsc#1170617, bsc#1170618).

  - x86/Hyper-V: Report crash register data when
    sysctl_record_panic_msg is not set (bsc#1170617,
    bsc#1170618).

  - x86: hyperv: report value of misc_features (git fixes).

  - x86/Hyper-V: Trigger crash enlightenment only once
    during system crash (bsc#1170617, bsc#1170618).

  - x86/Hyper-V: Unload vmbus channel in hv panic callback
    (bsc#1170617, bsc#1170618).

  - x86/kprobes: Avoid kretprobe recursion bug
    (bsc#1114279).

  - x86/resctrl: Fix invalid attempt at removing the default
    resource group (git-fixes).

  - x86/resctrl: Preserve CDP enable over CPU hotplug
    (bsc#1114279).

  - x86/unwind/orc: Do not skip the first frame for inactive
    tasks (bsc#1058115).

  - x86/unwind/orc: Fix error handling in __unwind_start()
    (bsc#1058115).

  - x86/unwind/orc: Fix error path for bad ORC entry type
    (bsc#1058115).

  - x86/unwind/orc: Fix unwind_get_return_address_ptr() for
    inactive tasks (bsc#1058115).

  - x86/unwind/orc: Prevent unwinding before ORC
    initialization (bsc#1058115).

  - x86/unwind: Prevent false warnings for non-current tasks
    (bsc#1058115).

  - x86/xen: fix booting 32-bit pv guest (bsc#1071995).

  - x86/xen: Make the boot CPU idle task reliable
    (bsc#1071995).

  - x86/xen: Make the secondary CPU idle tasks reliable
    (bsc#1071995).

  - xen/pci: reserve MCFG areas earlier (bsc#1170145).

  - xfrm: Always set XFRM_TRANSFORMED in
    xfrm(4,6)_output_finish (networking-stable-20_04_27).

  - xfs: clear PF_MEMALLOC before exiting xfsaild thread
    (git-fixes).

  - xfs: Correctly invert xfs_buftarg LRU isolation logic
    (git-fixes).

  - xfs: do not ever return a stale pointer from
    __xfs_dir3_free_read (git-fixes).

  - xprtrdma: Fix completion wait during device removal
    (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104745"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171952"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172453"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12659");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.52.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.52.3") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.52.3") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.52.3") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.52.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.52.1") ) flag++;

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
