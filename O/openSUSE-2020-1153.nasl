#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1153.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(139401);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/13");

  script_cve_id("CVE-2019-16746", "CVE-2019-20810", "CVE-2019-20908", "CVE-2020-0305", "CVE-2020-10135", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-10769", "CVE-2020-10773", "CVE-2020-10781", "CVE-2020-12771", "CVE-2020-12888", "CVE-2020-13974", "CVE-2020-14331", "CVE-2020-14416", "CVE-2020-15393", "CVE-2020-15780", "CVE-2020-16166");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-1153)");
  script_summary(english:"Check for the openSUSE-2020-1153 patch");

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

  - CVE-2019-16746: An issue was discovered in
    net/wireless/nl80211.c where it did not check the length
    of variable elements in a beacon head, leading to a
    buffer overflow (bnc#1152107 1173659).

  - CVE-2019-20810: go7007_snd_init in
    drivers/media/usb/go7007/snd-go7007.c did not call
    snd_card_free for a failure path, which causes a memory
    leak, aka CID-9453264ef586 (bnc#1172458).

  - CVE-2019-20908: An issue was discovered in
    drivers/firmware/efi/efi.c where Incorrect access
    permissions for the efivar_ssdt ACPI variable could be
    used by attackers to bypass lockdown or secure boot
    restrictions, aka CID-1957a85b0032 (bnc#1173567).

  - CVE-2020-0305: In cdev_get of char_dev.c, there is a
    possible use-after-free due to a race condition. This
    could lead to local escalation of privilege with System
    execution privileges needed. User interaction is not
    needed for exploitation (bnc#1174462).

  - CVE-2020-10135: Legacy pairing and secure-connections
    pairing authentication in Bluetooth&reg; BR/EDR Core
    Specification v5.2 and earlier may have allowed an
    unauthenticated user to complete authentication without
    pairing credentials via adjacent access. An
    unauthenticated, adjacent attacker could impersonate a
    Bluetooth BR/EDR master or slave to pair with a
    previously paired remote device to successfully complete
    the authentication procedure without knowing the link
    key (bnc#1171988).

  - CVE-2020-10766: Fixed rogue cross-process SSBD shutdown.
    Linux scheduler logical bug allowed an attacker to turn
    off the SSBD protection. (bnc#1172781).

  - CVE-2020-10767: Fixed indirect Branch Prediction Barrier
    is force-disabled when STIBP is unavailable or enhanced
    IBRS is available. (bnc#1172782).

  - CVE-2020-10768: Fixed indirect branch speculation can be
    enabled after it was force-disabled by the
    PR_SPEC_FORCE_DISABLE prctl command. (bnc#1172783).

  - CVE-2020-10769: A buffer over-read flaw was found in
    crypto_authenc_extractkeys in crypto/authenc.c in the
    IPsec Cryptographic algorithm's module, authenc. When a
    payload longer than 4 bytes, and is not following 4-byte
    alignment boundary guidelines, it causes a buffer
    over-read threat, leading to a system crash. This flaw
    allowed a local attacker with user privileges to cause a
    denial of service (bnc#1173265).

  - CVE-2020-10773: Fixed a kernel stack information leak on
    s390/s390x. (bnc#1172999).

  - CVE-2020-10781: A zram sysfs resource consumption was
    fixed. (bnc#1173074).

  - CVE-2020-12771: btree_gc_coalesce in
    drivers/md/bcache/btree.c has a deadlock if a coalescing
    operation fails (bnc#1171732).

  - CVE-2020-12888: The VFIO PCI driver mishandled attempts
    to access disabled memory space (bnc#1171868).

  - CVE-2020-13974: drivers/tty/vt/keyboard.c had an integer
    overflow if k_ascii was called several times in a row,
    aka CID-b86dab054059. (bnc#1172775).

  - CVE-2020-14331: Fixed a buffer over write in
    vgacon_scroll (bnc#1174205).

  - CVE-2020-14331: Fixed an out of bounds write to the
    vgacon scrollback buffer (bsc#1174205).

  - CVE-2020-14416: A race condition in tty->disc_data
    handling in the slip and slcan line discipline could
    lead to a use-after-free, aka CID-0ace17d56824. This
    affects drivers/net/slip/slip.c and
    drivers/net/can/slcan.c (bnc#1162002).

  - CVE-2020-15393: usbtest_disconnect in
    drivers/usb/misc/usbtest.c has a memory leak, aka
    CID-28ebeb8db770 (bnc#1173514).

  - CVE-2020-15780: An issue was discovered in
    drivers/acpi/acpi_configfs.c where injection of
    malicious ACPI tables via configfs could be used by
    attackers to bypass lockdown and secure boot
    restrictions, aka CID-75b0cea7bf30 (bnc#1173573).

  - CVE-2020-16166: The Linux kernel allowed remote
    attackers to make observations that help to obtain
    sensitive information about the internal state of the
    network RNG, aka CID-f227e3ec3b5c. This is related to
    drivers/char/random.c and kernel/time/timer.c
    (bnc#1174757).

The following non-security bugs were fixed :

  - ACPI: GED: add support for _Exx / _Lxx handler methods
    (bsc#1111666).

  - ACPI: GED: use correct trigger type field in _Exx / _Lxx
    handling (bsc#1111666).

  - ACPI: NFIT: Fix unlock on error in scrub_show()
    (bsc#1171753).

  - ACPI: PM: Avoid using power resources if there are none
    for D0 (bsc#1051510).

  - ACPI: sysfs: Fix pm_profile_attr type (bsc#1111666).

  - ACPI: video: Use native backlight on Acer Aspire 5783z
    (bsc#1111666).

  - ACPI: video: Use native backlight on Acer TravelMate
    5735Z (bsc#1111666).

  - ALSA: es1688: Add the missed snd_card_free()
    (bsc#1051510).

  - ALSA: hda: Add ElkhartLake HDMI codec vid (bsc#1111666).

  - ALSA: hda: add sienna_cichlid audio asic id for
    sienna_cichlid up (bsc#1111666).

  - ALSA: hda: fix NULL pointer dereference during suspend
    (git-fixes).

  - ALSA: hda/hdmi - enable runtime pm for newer AMD display
    audio (bsc#1111666).

  - ALSA: hda - let hs_mic be picked ahead of hp_mic
    (bsc#1111666).

  - ALSA: hda/realtek - add a pintbl quirk for several
    Lenovo machines (bsc#1111666).

  - ALSA: hda/realtek - Add LED class support for micmute
    LED (bsc#1111666).

  - ALSA: hda/realtek: Add mute LED and micmute LED support
    for HP systems (bsc#1111666).

  - ALSA: hda/realtek - Add quirk for Lenovo Carbon X1 8th
    gen (bsc#1111666).

  - ALSA: hda/realtek - Add quirk for MSI GE63 laptop
    (bsc#1111666).

  - ALSA: hda/realtek - Add quirk for MSI GL63
    (bsc#1111666).

  - ALSA: hda/realtek - change to suitable link model for
    ASUS platform (bsc#1111666).

  - ALSA: hda/realtek - Check headset type by unplug and
    resume (bsc#1111666).

  - ALSA: hda/realtek - Enable audio jacks of Acer
    vCopperbox with ALC269VC (bsc#1111666).

  - ALSA: hda/realtek: Enable headset mic of Acer C20-820
    with ALC269VC (bsc#1111666).

  - ALSA: hda/realtek: Enable headset mic of Acer TravelMate
    B311R-31 with ALC256 (bsc#1111666).

  - ALSA: hda/realtek: Enable headset mic of Acer Veriton
    N4660G with ALC269VC (bsc#1111666).

  - ALSA: hda/realtek: enable headset mic of ASUS ROG
    Zephyrus G14(G401) series with ALC289 (bsc#1111666).

  - ALSA: hda/realtek: enable headset mic of ASUS ROG
    Zephyrus G15(GA502) series with ALC289 (bsc#1111666).

  - ALSA: hda/realtek - Enable micmute LED on and HP system
    (bsc#1111666).

  - ALSA: hda/realtek - Enable Speaker for ASUS UX533 and
    UX534 (bsc#1111666).

  - ALSA: hda/realtek - Enable Speaker for ASUS UX563
    (bsc#1111666).

  - ALSA: hda/realtek: Fix add a 'ultra_low_power' function
    for intel reference board (alc256) (bsc#1111666).

  - ALSA: hda/realtek: Fixed ALC298 sound bug by adding
    quirk for Samsung Notebook Pen S (bsc#1111666).

  - ALSA: hda/realtek - Fixed HP right speaker no sound
    (bsc#1111666).

  - ALSA: hda/realtek - Fix Lenovo Thinkpad X1 Carbon 7th
    quirk subdevice id (bsc#1111666).

  - ALSA: hda/realtek - Fix unused variable warning w/o
    CONFIG_LEDS_TRIGGER_AUDIO (bsc#1111666).

  - ALSA: hda/realtek - Introduce polarity for micmute LED
    GPIO (bsc#1111666).

  - ALSA: hda/realtek: typo_fix: enable headset mic of ASUS
    ROG Zephyrus G14(GA401) series with ALC289
    (bsc#1111666).

  - ALSA: hda: Workaround for spurious wakeups on some Intel
    platforms (git-fixes).

  - ALSA: lx6464es - add support for LX6464ESe pci express
    variant (bsc#1111666).

  - ALSA: opl3: fix infoleak in opl3 (bsc#1111666).

  - ALSA: pcm: disallow linking stream to itself
    (bsc#1111666).

  - ALSA: usb-audio: Add duplex sound support for USB
    devices using implicit feedback (bsc#1111666).

  - ALSA: usb-audio: Add Pioneer DJ DJM-900NXS2 support
    (bsc#1111666).

  - ALSA: usb-audio: add quirk for MacroSilicon MS2109
    (bsc#1111666).

  - ALSA: usb-audio: Add vendor, product and profile name
    for HP Thunderbolt Dock (bsc#1111666).

  - ALSA: usb-audio: Clean up quirk entries with macros
    (bsc#1111666).

  - ALSA: usb-audio: Fix inconsistent card PM state after
    resume (bsc#1111666).

  - ALSA: usb-audio: Fix packet size calculation
    (bsc#1111666).

  - ALSA: usb-audio: Fix racy list management in output
    queue (bsc#1111666).

  - ALSA: usb-audio: Improve frames size computation
    (bsc#1111666).

  - ALSA: usb-audio: Manage auto-pm of all bundled
    interfaces (bsc#1111666).

  - ALSA: usb-audio: Use the new macro for HP Dock rename
    quirks (bsc#1111666).

  - amdgpu: a NULL ->mm does not mean a thread is a kthread
    (git-fixes).

  - arm64: map FDT as RW for early_init_dt_scan()
    (jsc#SLE-12423).

  - ath9k: Fix general protection fault in
    ath9k_hif_usb_rx_cb (bsc#1111666).

  - ath9k: Fix use-after-free Read in ath9k_wmi_ctrl_rx
    (bsc#1111666).

  - ath9k: Fix use-after-free Write in ath9k_htc_rx_msg
    (bsc#1111666).

  - ath9x: Fix stack-out-of-bounds Write in
    ath9k_hif_usb_rx_cb (bsc#1111666).

  - ax25: fix setsockopt(SO_BINDTODEVICE)
    (networking-stable-20_05_27).

  - b43: Fix connection problem with WPA3 (bsc#1111666).

  - b43_legacy: Fix connection problem with WPA3
    (bsc#1111666).

  - bcache: Fix an error code in bch_dump_read() (git fixes
    (block drivers)).

  - be2net: fix link failure after ethtool offline test
    (git-fixes).

  - block: Fix use-after-free in blkdev_get() (bsc#1174843).

  - block: nr_sects_write(): Disable preemption on seqcount
    write (bsc#1173818).

  - block: remove QUEUE_FLAG_STACKABLE (git fixes (block
    drivers)).

  - block: sed-opal: fix sparse warning: convert __be64 data
    (git fixes (block drivers)).

  - Bluetooth: Add SCO fallback for invalid LMP parameters
    error (bsc#1111666).

  - bnxt_en: Fix AER reset logic on 57500 chips (git-fixes).

  - bnxt_en: Fix ethtool selftest crash under error
    conditions (git-fixes).

  - bnxt_en: Fix handling FRAG_ERR when NVM_INSTALL_UPDATE
    cmd fails (git-fixes).

  - bnxt_en: Fix ipv6 RFS filter matching logic (git-fixes).

  - bnxt_en: fix NULL dereference in case SR-IOV
    configuration fails (git-fixes).

  - bnxt_en: Fix VF anti-spoof filter setup
    (networking-stable-20_05_12).

  - bnxt_en: Fix VLAN acceleration handling in
    bnxt_fix_features() (networking-stable-20_05_12).

  - bnxt_en: Improve AER slot reset
    (networking-stable-20_05_12).

  - brcmfmac: fix wrong location to get firmware feature
    (bsc#1111666).

  - brcmfmac: Transform compatible string for FW loading
    (bsc#1169771).

  - btrfs: add assertions for tree == inode->io_tree to
    extent IO helpers (bsc#1174438).

  - btrfs: add new helper btrfs_lock_and_flush_ordered_range
    (bsc#1174438).

  - btrfs: Always use a cached extent_state in
    btrfs_lock_and_flush_ordered_range (bsc#1174438).

  - btrfs: change timing for qgroup reserved space for
    ordered extents to fix reserved space leak
    (bsc#1172247).

  - btrfs: do not zero f_bavail if we have available space
    (bsc#1168081).

  - btrfs: drop argument tree from
    btrfs_lock_and_flush_ordered_range (bsc#1174438).

  - btrfs: file: reserve qgroup space after the hole punch
    range is locked (bsc#1172247).

  - btrfs: fix extent_state leak in
    btrfs_lock_and_flush_ordered_range (bsc#1174438).

  - btrfs: fix failure of RWF_NOWAIT write into prealloc
    extent beyond eof (bsc#1174438).

  - btrfs: fix hang on snapshot creation after RWF_NOWAIT
    write (bsc#1174438).

  - btrfs: fix RWF_NOWAIT write not failling when we need to
    cow (bsc#1174438).

  - btrfs: fix RWF_NOWAIT writes blocking on extent locks
    and waiting for IO (bsc#1174438).

  - btrfs: inode: move qgroup reserved space release to the
    callers of insert_reserved_file_extent() (bsc#1172247).

  - btrfs: inode: refactor the parameters of
    insert_reserved_file_extent() (bsc#1172247).

  - btrfs: make btrfs_ordered_extent naming consistent with
    btrfs_file_extent_item (bsc#1172247).

  - btrfs: qgroup: allow to unreserve range without
    releasing other ranges (bsc#1120163).

  - btrfs: qgroup: Fix a bug that prevents qgroup to be
    re-enabled after disable (bsc#1172247).

  - btrfs: qgroup: fix data leak caused by race between
    writeback and truncate (bsc#1172247).

  - btrfs: qgroup: remove ASYNC_COMMIT mechanism in favor of
    reserve retry-after-EDQUOT (bsc#1120163).

  - btrfs: qgroup: try to flush qgroup space when we get
    -EDQUOT (bsc#1120163).

  - btrfs: Return EAGAIN if we can't start no snpashot write
    in check_can_nocow (bsc#1174438).

  - btrfs: use correct count in btrfs_file_write_iter()
    (bsc#1174438).

  - btrfs: Use newly introduced
    btrfs_lock_and_flush_ordered_range (bsc#1174438).

  - btrfs: volumes: Remove ENOSPC-prone btrfs_can_relocate()
    (bsc#1171124).

  - bus: hisi_lpc: Add .remove method to avoid driver unbind
    crash (bsc#1174658).

  - bus: hisi_lpc: Do not fail probe for unrecognised child
    devices (bsc#1174658).

  - bus: hisi_lpc: Unregister logical PIO range to avoid
    potential use-after-free (bsc#1174658).

  - bus: sunxi-rsb: Return correct data when mixing 16-bit
    and 8-bit reads (bsc#1111666).

  - carl9170: remove P2P_GO support (bsc#1111666).

  - cdc-acm: Add DISABLE_ECHO quirk for Microchip/SMSC chip
    (git-fixes).

  - CDC-ACM: heed quirk also in error handling (git-fixes).

  - ceph: convert mdsc->cap_dirty to a per-session list
    (bsc#1167104).

  - ceph: request expedited service on session's last cap
    flush (bsc#1167104).

  - cgroup, blkcg: Prepare some symbols for module and
    !CONFIG_CGROUP usages (bsc#1173857).

  - char/random: Add a newline at the end of the file
    (jsc#SLE-12423).

  - cifs: get rid of unused parameter in
    reconn_setup_dfs_targets() (bsc#1144333).

  - cifs: handle hostnames that resolve to same ip in
    failover (bsc#1144333 bsc#1161016).

  - cifs: set up next DFS target before generic_ip_connect()
    (bsc#1144333 bsc#1161016).

  - clk: bcm2835: Fix return type of bcm2835_register_gate
    (bsc#1051510).

  - clk: clk-flexgen: fix clock-critical handling
    (bsc#1051510).

  - clk: sunxi: Fix incorrect usage of round_down()
    (bsc#1051510).

  - clocksource: dw_apb_timer: Make CPU-affiliation being
    optional (bsc#1111666).

  - compat_ioctl: block: handle BLKREPORTZONE/BLKRESETZONE
    (git fixes (block drivers)).

  - compat_ioctl: block: handle Persistent Reservations (git
    fixes (block drivers)).

  - config: arm64: enable CONFIG_IOMMU_DEFAULT_PASSTHROUGH
    References: bsc#1174549

  - copy_(to,from)_user(): consolidate object size checks
    (git fixes).

  - crypto: algboss - do not wait during notifier callback
    (bsc#1111666).

  - crypto: algif_skcipher - Cap recv SG list at ctx->used
    (bsc#1111666).

  - crypto: caam - update xts sector size for large input
    length (bsc#1111666).

  - crypto: cavium/nitrox - Fix 'nitrox_get_first_device()'
    when ndevlist is fully iterated (bsc#1111666).

  - crypto: cavium/nitrox - Fix 'nitrox_get_first_device()'
    when ndevlist is fully iterated (git-fixes).

  - crypto/chcr: fix for ccm(aes) failed test (bsc#1111666).

  - crypto: chelsio/chtls: properly set tp->lsndtime
    (bsc#1111666).

  - crypto: rockchip - fix scatterlist nents error
    (git-fixes).

  - crypto: stm32/crc32 - fix ext4 chksum BUG_ON()
    (git-fixes).

  - crypto: talitos - check AES key size (git-fixes).

  - crypto: talitos - fix ablkcipher for CONFIG_VMAP_STACK
    (git-fixes).

  - crypto: talitos - fix IPsec cipher in length
    (git-fixes).

  - crypto: talitos - reorder code in talitos_edesc_alloc()
    (git-fixes).

  - crypto: virtio: Fix src/dst scatterlist calculation in
    __virtio_crypto_skcipher_do_req() (git-fixes).

  - debugfs: Check module state before warning in
    (full/open)_proxy_open() (bsc#1173746).

  - devinet: fix memleak in inetdev_init()
    (networking-stable-20_06_07).

  - /dev/mem: Add missing memory barriers for devmem_inode
    (git-fixes).

  - /dev/mem: Revoke mappings when a driver claims the
    region (git-fixes).

  - dlm: remove BUG() before panic() (bsc#1174844).

  - dmaengine: tegra210-adma: Fix an error handling path in
    'tegra_adma_probe()' (bsc#1111666).

  - dm btree: increase rebalance threshold in __rebalance2()
    (git fixes (block drivers)).

  - dm cache: fix a crash due to incorrect work item
    cancelling (git fixes (block drivers)).

  - dm crypt: fix benbi IV constructor crash if used in
    authenticated mode (git fixes (block drivers)).

  - dm: fix potential for q->make_request_fn NULL pointer
    (git fixes (block drivers)).

  - dm space map common: fix to ensure new block isn't
    already in use (git fixes (block drivers)).

  - dm: various cleanups to md->queue initialization code
    (git fixes).

  - dm verity fec: fix hash block number in
    verity_fec_decode (git fixes (block drivers)).

  - dm verity fec: fix memory leak in verity_fec_dtr (git
    fixes (block drivers)).

  - dpaa_eth: fix usage as DSA master, try 3
    (networking-stable-20_05_27).

  - driver-core, libnvdimm: Let device subsystems add local
    lockdep coverage (bsc#1171753)

  - Drivers: hv: Change flag to write log level in panic msg
    to false (bsc#1170617, bsc#1170618).

  - drivers: soc: ti: knav_qmss_queue: Make
    knav_gp_range_ops static (bsc#1051510).

  - drm: amd/display: fix Kconfig help text (bsc#1113956)
    &#9;* only fix DEBUG_KERNEL_DC

  - drm: bridge: adv7511: Extend list of audio sample rates
    (bsc#1111666).

  - drm/dp_mst: Increase ACT retry timeout to 3s
    (bsc#1113956) * context changes

  - drm: encoder_slave: fix refcouting error for modules
    (bsc#1111666).

  - drm: encoder_slave: fix refcouting error for modules
    (bsc#1114279)

  - drm/i915/icl+: Fix hotplug interrupt disabling after
    storm detection (bsc#1112178)

  - drm/i915: Whitelist context-local timestamp in the gen9
    cmdparser (bsc#1111666).

  - drm/mediatek: Check plane visibility in atomic_update
    (bsc#1113956) * context changes

  - drm/msm/dpu: fix error return code in dpu_encoder_init
    (bsc#1111666).

  - drm: panel-orientation-quirks: Add quirk for Asus T101HA
    panel (bsc#1111666).

  - drm: panel-orientation-quirks: Use generic
    orientation-data for Acer S1003 (bsc#1111666).

  - drm/qxl: Use correct notify port address when creating
    cursor ring (bsc#1113956)

  - drm/radeon: fix double free (bsc#1113956)

  - drm/radeon: fix fb_div check in ni_init_smc_spll_table()
    (bsc#1113956)

  - drm/sun4i: hdmi ddc clk: Fix size of m divider
    (bsc#1111666).

  - drm/tegra: hub: Do not enable orphaned window group
    (bsc#1111666).

  - drm/vkms: Hold gem object while still in-use
    (bsc#1113956) * context changes

  - e1000: Distribute switch variables for initialization
    (bsc#1111666).

  - e1000e: Disable TSO for buffer overrun workaround
    (bsc#1051510).

  - e1000e: Do not wake up the system via WOL if device
    wakeup is disabled (bsc#1051510).

  - e1000e: Relax condition to trigger reset for ME
    workaround (bsc#1111666).

  - EDAC/amd64: Read back the scrub rate PCI register on
    F15h (bsc#1114279).

  - efi/memreserve: deal with memreserve entries in unmapped
    memory (bsc#1174685).

  - efi/random: Increase size of firmware supplied
    randomness (jsc#SLE-12423).

  - efi/random: Treat EFI_RNG_PROTOCOL output as bootloader
    randomness (jsc#SLE-12423).

  - efi: READ_ONCE rng seed size before munmap
    (jsc#SLE-12423).

  - efi: Reorder pr_notice() with add_device_randomness()
    call (jsc#SLE-12423).

  - evm: Check also if *tfm is an error pointer in
    init_desc() (bsc#1051510).

  - evm: Fix a small race in init_desc() (bsc#1051510).

  - ext4: fix a data race at inode->i_blocks (bsc#1171835).

  - ext4: fix EXT_MAX_EXTENT/INDEX to check for zeroed
    eh_max (bsc#1174840).

  - ext4: fix partial cluster initialization when splitting
    extent (bsc#1173839).

  - ext4: fix race between ext4_sync_parent() and rename()
    (bsc#1173838).

  - ext4, jbd2: ensure panic by fix a race between jbd2
    abort and ext4 error handlers (bsc#1173833).

  - extcon: adc-jack: Fix an error handling path in
    'adc_jack_probe()' (bsc#1051510).

  - fanotify: fix ignore mask logic for events on child and
    on dir (bsc#1172719).

  - fat: do not allow to mount if the FAT length == 0
    (bsc#1174845).

  - fdt: add support for rng-seed (jsc#SLE-12423).

  - fdt: Update CRC check for rng-seed (jsc#SLE-12423).

  - firmware: imx: scu: Fix corruption of header
    (git-fixes).

  - firmware: imx: scu: Fix possible memory leak in
    imx_scu_probe() (bsc#1111666).

  - fix multiplication overflow in copy_fdtable()
    (bsc#1173825).

  - Fix Patch-mainline tag in the previous zram fix patch

  - fpga: dfl: fix bug in port reset handshake (git-fixes).

  - fq_codel: fix TCA_FQ_CODEL_DROP_BATCH_SIZE sanity checks
    (networking-stable-20_05_12).

  - gpiolib: Document that GPIO line names are not globally
    unique (bsc#1051510).

  - gpu: host1x: Detach driver on unregister (bsc#1111666).

  - gpu: ipu-v3: pre: do not trigger update if buffer
    address does not change (bsc#1111666).

  - HID: hiddev: fix mess in hiddev_open() (git-fixes).

  - HID: magicmouse: do not set up autorepeat (git-fixes).

  - HID: sony: Fix for broken buttons on DS3 USB dongles
    (bsc#1051510).

  - HISI LPC: Re-Add ACPI child enumeration support
    (bsc#1174658).

  - HISI LPC: Stop using MFD APIs (bsc#1174658).

  - hv_netvsc: Fix netvsc_start_xmit's return type
    (git-fixes).

  - hwmon: (acpi_power_meter) Fix potential memory leak in
    acpi_power_meter_add() (bsc#1111666).

  - hwmon: (emc2103) fix unable to change fan pwm1_enable
    attribute (bsc#1111666).

  - hwmon: (max6697) Make sure the OVERT mask is set
    correctly (bsc#1111666).

  - i2c: algo-pca: Add 0x78 as SCL stuck low status for
    PCA9665 (bsc#1111666).

  - i2c: eg20t: Load module automatically if ID matches
    (bsc#1111666).

  - i2c: mlxcpld: check correct size of maximum RECV_LEN
    packet (bsc#1111666).

  - i40e: reduce stack usage in i40e_set_fc (git-fixes).

  - IB/hfi1: Do not destroy hfi1_wq when the device is shut
    down (bsc#1174409).

  - IB/hfi1: Do not destroy link_wq when the device is shut
    down (bsc#1174409).

  - ibmveth: Fix max MTU limit (bsc#1173428 ltc#186397).

  - ibmvnic: continue to init in CRQ reset returns H_CLOSED
    (bsc#1173280 ltc#185369).

  - ibmvnic: Flush existing work items before device removal
    (bsc#1065729).

  - ibmvnic: Harden device login requests (bsc#1170011
    ltc#183538).

  - iio: buffer: Do not allow buffers without any channels
    enabled to be activated (bsc#1051510).

  - iio:health:afe4404 Fix timestamp alignment and prevent
    data leak (bsc#1111666).

  - iio:humidity:hdc100x Fix alignment and data leak issues
    (bsc#1111666).

  - iio:magnetometer:ak8974: Fix alignment and data leak
    issues (bsc#1111666).

  - iio: mma8452: Add missed iio_device_unregister() call in
    mma8452_probe() (bsc#1111666).

  - iio: pressure: bmp280: Tolerate IRQ before registering
    (bsc#1051510).

  - iio:pressure:ms5611 Fix buffer element alignment
    (bsc#1111666).

  - iio: pressure: zpa2326: handle pm_runtime_get_sync
    failure (bsc#1111666).

  - ima: Directly assign the ima_default_policy pointer to
    ima_rules (bsc#1051510).

  - ima: Fix ima digest hash table key calculation
    (bsc#1051510).

  - include/asm-generic/topology.h: guard cpumask_of_node()
    macro argument (bsc#1148868).

  - input: i8042 - add Lenovo XiaoXin Air 12 to i8042 nomux
    list (bsc#1111666).

  - input: i8042 - Remove special PowerPC handling
    (git-fixes).

  - input: synaptics - add a second working PNP_ID for
    Lenovo T470s (bsc#1111666).

  - intel_idle: Graceful probe failure when MWAIT is
    disabled (bsc#1174115).

  - intel_th: Fix a NULL dereference when hub driver is not
    loaded (bsc#1111666).

  - io-mapping: indicate mapping failure (git-fixes).

  - ipvlan: call dev_change_flags when ipvlan mode is reset
    (git-fixes).

  - ixgbevf: Remove limit of 10 entries for unicast filter
    list (git-fixes).

  - jbd2: avoid leaking transaction credits when unreserving
    handle (bsc#1173845).

  - jbd2: Preserve kABI when adding j_abort_mutex
    (bsc#1173833).

  - kabi: hv: prevent struct device_node to become defined
    (bsc#1172871).

  - kabi: ppc64le: prevent struct dma_map_ops to become
    defined (jsc#SLE-12423).

  - kABI: protect struct mlx5_cmd_work_ent (kabi).

  - kABI: reintroduce inet_hashtables.h include to l2tp_ip
    (kabi).

  - kernfs: fix barrier usage in __kernfs_new_node()
    (bsc#1111666).

  - kvm: nVMX: Do not reread VMCS-agnostic state when
    switching VMCS (bsc#1114279).

  - kvm: nVMX: Skip IBPB when switching between vmcs01 and
    vmcs02 (bsc#1114279).

  - kvm: x86: Fix APIC page invalidation race (bsc#1174122).

  - kvm: x86: Fix L1TF mitigation for shadow MMU
    (bsc#1171904).

  - kvm: x86/mmu: Set mmio_value to '0' if reserved #PF
    can't be generated (bsc#1171904).

  - kvm: x86: only do L1TF workaround on affected processors
    (bsc#1171904).

  - l2tp: add sk_family checks to l2tp_validate_socket
    (networking-stable-20_06_07).

  - l2tp: do not use inet_hash()/inet_unhash()
    (networking-stable-20_06_07).

  - libceph: do not omit recovery_deletes in target_copy()
    (bsc#1174113).

  - libceph: ignore pool overlay and cache logic on
    redirects (bsc#1173146).

  - lib: logic_pio: Add logic_pio_unregister_range()
    (bsc#1174658).

  - lib: logic_pio: Avoid possible overlap for unregistering
    regions (bsc#1174658).

  - lib: logic_pio: Fix RCU usage (bsc#1174658).

  - libnvdimm/bus: Fix wait_nvdimm_bus_probe_idle() ABBA
    deadlock (bsc#1171753).

  - libnvdimm/bus: Prepare the nd_ioctl() path to be
    re-entrant (bsc#1171753).

  - libnvdimm/bus: Stop holding nvdimm_bus_list_mutex over
    __nd_ioctl() (bsc#1171753).

  - libnvdimm: cover up changes in struct nvdimm_bus
    (bsc#1171753).

  - libnvdimm: cover up nd_pfn_sb changes (bsc#1171759).

  - libnvdimm/dax: Pick the right alignment default when
    creating dax devices (bsc#1171759).

  - libnvdimm/label: Remove the dpa align check
    (bsc#1171759).

  - libnvdimm/of_pmem: Provide a unique name for bus
    provider (bsc#1171739).

  - libnvdimm/pfn_dev: Add a build check to make sure we
    notice when struct page size change (bsc#1171743).

  - libnvdimm/pfn_dev: Add page size and struct page size to
    pfn superblock (bsc#1171759).

  - libnvdimm/pfn: Prevent raw mode fallback if
    pfn-infoblock valid (bsc#1171743).

  - libnvdimm/pmem: Advance namespace seed for specific
    probe errors (bsc#1171743).

  - libnvdimm/region: Initialize bad block for volatile
    namespaces (bnc#1151927 5.3.6).

  - libnvdimm/region: Rewrite _probe_success() to
    _advance_seeds() (bsc#1171743).

  - libnvdimm: Use PAGE_SIZE instead of SZ_4K for align
    check (bsc#1171759).

  - livepatch: Apply vmlinux-specific KLP relocations early
    (bsc#1071995).

  - livepatch: Disallow vmlinux.ko (bsc#1071995).

  - livepatch: Make klp_apply_object_relocs static
    (bsc#1071995).

  - livepatch: Prevent module-specific KLP rela sections
    from referencing vmlinux symbols (bsc#1071995).

  - livepatch: Remove .klp.arch (bsc#1071995).

  - loop: replace kill_bdev with invalidate_bdev
    (bsc#1173820).

  - lpfc_debugfs: get rid of pointless access_ok()
    (bsc#1172687 bsc#1171530).

  - lpfc: Synchronize NVME transport and lpfc driver
    devloss_tmo (bcs#1173060).

  - mac80211: add option for setting control flags
    (bsc#1111666).

  - mac80211: set IEEE80211_TX_CTRL_PORT_CTRL_PROTO for
    nl80211 TX (bsc#1111666).

  - mailbox: imx: Disable the clock on
    devm_mbox_controller_register() failure (git-fixes).

  - md: Avoid namespace collision with bitmap API (git fixes
    (block drivers)).

  - mdraid: fix read/write bytes accounting (bsc#1172537).

  - md: use memalloc scope APIs in
    mddev_suspend()/mddev_resume() (bsc#1166985)).

  - media: cec: silence shift wrapping warning in
    __cec_s_log_addrs() (git-fixes).

  - media: si2157: Better check for running tuner in init
    (bsc#1111666).

  - mlxsw: core: Do not use WQ_MEM_RECLAIM for mlxsw ordered
    workqueue (git-fixes).

  - mlxsw: core: Do not use WQ_MEM_RECLAIM for mlxsw
    workqueue (git-fixes).

  - mlxsw: pci: Return error on PCI reset timeout
    (git-fixes).

  - mlxsw: spectrum_acl_tcam: Position vchunk in a vregion
    list properly (networking-stable-20_05_12).

  - mlxsw: spectrum: Disallow prio-tagged packets when PVID
    is removed (git-fixes).

  - mlxsw: spectrum_dpipe: Add missing error path
    (git-fixes).

  - mlxsw: spectrum: Prevent force of 56G (git-fixes).

  - mlxsw: spectrum_router: Refresh nexthop neighbour when
    it becomes dead (git-fixes).

  - mlxsw: spectrum_router: Remove inappropriate usage of
    WARN_ON() (git-fixes).

  - mlxsw: spectrum_switchdev: Add MDB entries in prepare
    phase (git-fixes).

  - mlxsw: spectrum_switchdev: Do not treat static FDB
    entries as sticky (git-fixes).

  - mmc: block: Fix request completion in the CQE timeout
    path (bsc#1111666).

  - mmc: block: Fix use-after-free issue for rpmb
    (bsc#1111666).

  - mmc: fix compilation of user API (bsc#1051510).

  - mmc: sdhci: do not enable card detect interrupt for gpio
    cd type (bsc#1111666).

  - mmc: sdhci-msm: Set SDHCI_QUIRK_MULTIBLOCK_READ_ACMD12
    quirk (bsc#1111666).

  - Move kabi patch into the right place

  - Move upstreamed lpfc patches into sorted section

  - mvpp2: remove misleading comment (git-fixes).

  - net: be more gentle about silly gso requests coming from
    user (networking-stable-20_06_07).

  - net: check untrusted gso_size at kernel entry
    (networking-stable-20_06_07).

  - net/cxgb4: Check the return from t4_query_params
    properly (git-fixes).

  - net: dsa: bcm_sf2: Fix node reference count (git-fixes).

  - net: dsa: loop: Add module soft dependency
    (networking-stable-20_05_16).

  - net: dsa: mt7530: fix roaming from DSA user ports
    (networking-stable-20_05_27).

  - net: ena: add intr_moder_rx_interval to struct
    ena_com_dev and use it (git-fixes).

  - net: ena: add missing ethtool TX timestamping indication
    (git-fixes).

  - net: ena: avoid memory access violation by validating
    req_id properly (git-fixes).

  - net: ena: do not wake up tx queue when down (git-fixes).

  - net: ena: ena-com.c: prevent NULL pointer dereference
    (git-fixes).

  - net: ena: ethtool: use correct value for crc32 hash
    (git-fixes).

  - net: ena: fix continuous keep-alive resets (git-fixes).

  - net: ena: fix corruption of dev_idx_to_host_tbl
    (git-fixes).

  - net: ena: fix default tx interrupt moderation interval
    (git-fixes).

  - net: ena: fix incorrect default RSS key (git-fixes).

  - net: ena: fix incorrectly saving queue numbers when
    setting RSS indirection table (git-fixes).

  - net: ena: fix issues in setting interrupt moderation
    params in ethtool (git-fixes).

  - net: ena: fix potential crash when rxfh key is NULL
    (git-fixes).

  - net: ena: fix retrieval of nonadaptive interrupt
    moderation intervals (git-fixes).

  - net: ena: fix uses of round_jiffies() (git-fixes).

  - net: ena: make ena rxfh support ETH_RSS_HASH_NO_CHANGE
    (git-fixes).

  - net: ena: reimplement set/get_coalesce() (git-fixes).

  - net: ena: rss: do not allocate key when not supported
    (git-fixes).

  - net: ena: rss: fix failure to get indirection table
    (git-fixes).

  - net: ena: rss: store hash function as values and not
    bits (git-fixes).

  - netfilter: connlabels: prefer static lock initialiser
    (git-fixes).

  - netfilter: ctnetlink: netns exit must wait for callbacks
    (bsc#1169795).

  - netfilter: not mark a spinlock as __read_mostly
    (git-fixes).

  - net: fix a potential recursive NETDEV_FEAT_CHANGE
    (networking-stable-20_05_16).

  - net: hns3: add autoneg and change speed support for
    fibre port (bsc#1174070).

  - net: hns3: add support for FEC encoding control
    (bsc#1174070).

  - net: hns3: add support for multiple media type
    (bsc#1174070).

  - net: hns3: fix a not link up issue when fibre port
    supports autoneg (bsc#1174070).

  - net: hns3: fix for FEC configuration (bsc#1174070).

  - net: hns3: fix port capbility updating issue
    (bsc#1174070).

  - net: hns3: fix port setting handle for fibre port
    (bsc#1174070).

  - net: hns3: fix selftest fail issue for fibre port with
    autoneg on (bsc#1174070).

  - net: hns3: restore the MAC autoneg state after reset
    (bsc#1174070).

  - net: inet_csk: Fix so_reuseport bind-address cache in
    tb->fast* (networking-stable-20_05_27).

  - net: ipip: fix wrong address family in init error path
    (networking-stable-20_05_27).

  - net: ipvlan: Fix ipvlan device tso disabled while
    NETIF_F_IP_CSUM is set (git-fixes).

  - net: macsec: preserve ingress frame ordering
    (networking-stable-20_05_12).

  - net/mlx4_core: drop useless LIST_HEAD (git-fixes).

  - net/mlx4_core: fix a memory leak bug (git-fixes).

  - net/mlx4_core: Fix use of ENOSPC around
    mlx4_counter_alloc() (networking-stable-20_05_12).

  - net/mlx5: Add command entry handling completion
    (networking-stable-20_05_27).

  - net/mlx5: Avoid panic when setting vport rate
    (git-fixes).

  - net/mlx5: Continue driver initialization despite debugfs
    failure (git-fixes).

  - net/mlx5e: ethtool, Fix a typo in WOL function names
    (git-fixes).

  - net/mlx5e: Fix traffic duplication in ethtool steering
    (git-fixes).

  - net/mlx5e: Remove unnecessary clear_bit()s (git-fixes).

  - net/mlx5e: Update netdev txq on completions during
    closure (networking-stable-20_05_27).

  - net/mlx5: Fix command entry leak in Internal Error State
    (networking-stable-20_05_12).

  - net/mlx5: Fix crash upon suspend/resume
    (networking-stable-20_06_07).

  - net/mlx5: Fix forced completion access non initialized
    command entry (networking-stable-20_05_12).

  - net: mvmdio: allow up to four clocks to be specified for
    orion-mdio (git-fixes).

  - net: mvpp2: prs: Do not override the sign bit in SRAM
    parser shift (git-fixes).

  - net: phy: fix aneg restart in phy_ethtool_set_eee
    (networking-stable-20_05_16).

  - netprio_cgroup: Fix unlimited memory leak of v2 cgroups
    (networking-stable-20_05_16).

  - net: qede: stop adding events on an already destroyed
    workqueue (git-fixes).

  - net: qed: fix excessive QM ILT lines consumption
    (git-fixes).

  - net: qed: fix NVMe login fails over VFs (git-fixes).

  - net: qrtr: Fix passing invalid reference to
    qrtr_local_enqueue() (networking-stable-20_05_27).

  - net: revert 'net: get rid of an signed integer overflow
    in ip_idents_reserve()' (networking-stable-20_05_27).

  - net sched: fix reporting the first-time use timestamp
    (networking-stable-20_05_27).

  - net: stricter validation of untrusted gso packets
    (networking-stable-20_05_12).

  - net/tls: Fix sk_psock refcnt leak in
    bpf_exec_tx_verdict() (networking-stable-20_05_12).

  - net/tls: Fix sk_psock refcnt leak when in
    tls_data_ready() (networking-stable-20_05_12).

  - net: usb: qmi_wwan: add support for DW5816e
    (networking-stable-20_05_12).

  - net: usb: qmi_wwan: add Telit 0x1050 composition
    (networking-stable-20_06_07).

  - net: usb: qmi_wwan: add Telit LE910C1-EUX composition
    (networking-stable-20_06_07).

  - net: vmxnet3: fix possible buffer overflow caused by bad
    DMA value in vmxnet3_get_rss() (bsc#1172484).

  - nfp: bpf: fix code-gen bug on BPF_ALU | BPF_XOR | BPF_K
    (git-fixes).

  - NFS: Fix an RCU lock leak in
    nfs4_refresh_delegation_stateid() (bsc#1170592).

  - NFSv4: Retry CLOSE and DELEGRETURN on
    NFS4ERR_OLD_STATEID (bsc#1170592).

  - nilfs2: fix NULL pointer dereference at
    nilfs_segctor_do_construct() (bsc#1173857).

  - nl80211: fix NL80211_ATTR_CHANNEL_WIDTH attribute type
    (bsc#1111666).

  - nvdimm: Avoid race between probe and reading device
    attributes (bsc#1170442).

  - nvme: check for NVME_CTRL_LIVE in nvme_report_ns_ids()
    (bcs#1171558 bsc#1159058).

  - nvme: do not update multipath disk information if the
    controller is down (bcs#1171558 bsc#1159058).

  - nvme: fail cancelled commands with
    NVME_SC_HOST_PATH_ERROR (bsc#1158983 bsc#1172538).

  - nvme-fc: Fail transport errors with NVME_SC_HOST_PATH
    (bsc#1158983 bsc#1172538).

  - nvme-tcp: fail command with NVME_SC_HOST_PATH_ERROR send
    failed (bsc#1158983 bsc#1172538).

  - objtool: Clean instruction state before each function
    validation (bsc#1169514).

  - objtool: Ignore empty alternatives (bsc#1169514).

  - ocfs2: avoid inode removal while nfsd is accessing it
    (bsc#1172963).

  - ocfs2: fix panic on nfs server over ocfs2 (bsc#1172963).

  - ocfs2: load global_inode_alloc (bsc#1172963).

  - ocfs2: no need try to truncate file beyond i_size
    (bsc#1171841).

  - overflow: Fix -Wtype-limits compilation warnings (git
    fixes).

  - overflow.h: Add arithmetic shift helper (git fixes).

  - p54usb: add AirVasT USB stick device-id (bsc#1051510).

  - padata: ensure the reorder timer callback runs on the
    correct CPU (git-fixes).

  - padata: reorder work kABI fixup (git-fixes).

  - PCI/AER: Remove HEST/FIRMWARE_FIRST parsing for AER
    ownership (bsc#1174356).

  - PCI/AER: Use only _OSC to determine AER ownership
    (bsc#1174356).

  - PCI: Allow pci_resize_resource() for devices on root bus
    (bsc#1051510).

  - PCI: Fix pci_register_host_bridge() device_register()
    error handling (bsc#1051510).

  - PCI: Fix 'try' semantics of bus and slot reset
    (git-fixes).

  - PCI: Generalize multi-function power dependency device
    links (bsc#1111666).

  - PCI: hv: Change pci_protocol_version to per-hbus
    (bsc#1172871, bsc#1172872).

  - PCI: hv: Fix the PCI HyperV probe failure path to
    release resource properly (bsc#1172871, bsc#1172872).

  - PCI: hv: Introduce hv_msi_entry (bsc#1172871,
    bsc#1172872).

  - PCI: hv: Move hypercall related definitions into tlfs
    header (bsc#1172871, bsc#1172872).

  - PCI: hv: Move retarget related structures into tlfs
    header (bsc#1172871, bsc#1172872).

  - PCI: hv: Reorganize the code in preparation of
    hibernation (bsc#1172871, bsc#1172872).

  - PCI: hv: Retry PCI bus D0 entry on invalid device state
    (bsc#1172871, bsc#1172872).

  - PCI: pciehp: Fix indefinite wait on sysfs requests
    (git-fixes).

  - PCI: pciehp: Support interrupts sent from D3hot
    (git-fixes).

  - PCI: Program MPS for RCiEP devices (bsc#1051510).

  - PCI/PTM: Inherit Switch Downstream Port PTM settings
    from Upstream Port (bsc#1051510).

  - pci: Revive pci_dev __aer_firmware_first* fields for
    kABI (bsc#1174356).

  - pcm_native: result of put_user() needs to be checked
    (bsc#1111666).

  - perf/x86/amd: Constrain Large Increment per Cycle events
    (git-fixes).

  - perf/x86/amd/ibs: Fix reading of the IBS OpData register
    and thus precise RIP validity (git-fixes).

  - perf/x86/amd/ibs: Fix sample bias for dispatched
    micro-ops (git-fixes).

  - perf/x86/amd/ibs: Handle erratum #420 only on the
    affected CPU family (10h) (git-fixes).

  - perf/x86/amd/iommu: Make the 'amd_iommu_attr_groups'
    symbol static (git-fixes).

  - perf/x86/amd/uncore: Do not set 'ThreadMask' and
    'SliceMask' for non-L3 PMCs (git-fixes stable).

  - perf/x86/amd/uncore: Set the thread mask for F17h L3
    PMCs (git-fixes).

  - perf/x86/amd/uncore: Set ThreadMask and SliceMask for L3
    Cache perf events (git-fixes stable).

  - perf/x86: Enable free running PEBS for REGS_USER/INTR
    (git-fixes).

  - perf/x86: Fix incorrect PEBS_REGS (git-fixes).

  - perf/x86/intel: Add generic branch tracing check to
    intel_pmu_has_bts() (git-fixes).

  - perf/x86/intel: Add proper condition to run sched_task
    callbacks (git-fixes).

  - perf/x86/intel/bts: Fix the use of page_private()
    (git-fixes).

  - perf/x86/intel: Fix PT PMI handling (git-fixes).

  - perf/x86/intel: Move branch tracing setup to the
    Intel-specific source file (git-fixes).

  - perf/x86/intel/uncore: Add Node ID mask (git-fixes).

  - perf/x86/intel/uncore: Fix PCI BDF address of M3UPI on
    SKX (git-fixes).

  - perf/x86/intel/uncore: Handle invalid event coding for
    free-running counter (git-fixes).

  - perf/x86/uncore: Fix event group support (git-fixes).

  - pid: Improve the comment about waiting in
    zap_pid_ns_processes (git fixes)).

  - pinctrl: freescale: imx: Fix an error handling path in
    'imx_pinctrl_probe()' (bsc#1051510).

  - pinctrl: imxl: Fix an error handling path in
    'imx1_pinctrl_core_probe()' (bsc#1051510).

  - pinctrl: samsung: Save/restore eint_mask over suspend
    for EINT_TYPE GPIOs (bsc#1051510).

  - platform/x86: dell-laptop: do not register micmute LED
    if there is no token (bsc#1111666).

  - platform/x86: hp-wmi: Convert simple_strtoul() to
    kstrtou32() (bsc#1111666).

  - PM / Domains: Allow genpd users to specify default
    active wakeup behavior (git-fixes).

  - pnp: Use list_for_each_entry() instead of open coding
    (git fixes).

  - powerpc/64s: Do not let DT CPU features set FSCR_DSCR
    (bsc#1065729).

  - powerpc/64s: Save FSCR to init_task.thread.fscr after
    feature init (bsc#1065729).

  - powerpc/book3s64: Export has_transparent_hugepage()
    related functions (bsc#1171759).

  - powerpc/book3s64/pkeys: Fix pkey_access_permitted() for
    execute disable pkey (bsc#1065729).

  - powerpc/fadump: fix race between pstore write and fadump
    crash trigger (bsc#1168959 ltc#185010).

  -
    powerpc-mm-Remove-kvm-radix-prefetch-workaround-for-.pat
    ch

  - powerpc/xive: Clear the page tables for the ESB IO
    mapping (bsc#1085030).

  - powerpc-xmon-don-t-access-ASDR-in-VMs.patch

  - powerpc/xmon: Reset RCU and soft lockup watchdogs
    (bsc#1065729).

  - power: supply: bq24257_charger: Replace depends on
    REGMAP_I2C with select (bsc#1051510).

  - power: supply: lp8788: Fix an error handling path in
    'lp8788_charger_probe()' (bsc#1051510).

  - power: supply: smb347-charger: IRQSTAT_D is volatile
    (bsc#1051510).

  - power: vexpress: add suppress_bind_attrs to true
    (bsc#1111666).

  - pppoe: only process PADT targeted at local interfaces
    (networking-stable-20_05_16).

  - propagate_one(): mnt_set_mountpoint() needs mount_lock
    (bsc#1174841).

  - qed: reduce maximum stack frame size (git-fixes).

  - qlcnic: fix missing release in
    qlcnic_83xx_interrupt_test (git-fixes).

  - r8152: support additional Microsoft Surface Ethernet
    Adapter variant (networking-stable-20_05_27).

  - raid5: remove gfp flags from scribble_alloc()
    (bsc#1166985).

  - RDMA/efa: Fix setting of wrong bit in get/set_feature
    commands (bsc#1111666)

  - RDMA/efa: Set maximum pkeys device attribute
    (bsc#1111666)

  - RDMA/efa: Support remote read access in MR registration
    (bsc#1111666)

  - RDMA/efa: Unified getters/setters for device structs
    bitmask access (bsc#1111666)

  - README.BRANCH: Add Takashi Iwai as primary maintainer.

  - regmap: debugfs: Do not sleep while atomic for fast_io
    regmaps (bsc#1111666).

  - Revert 'bcache: ignore pending signals when creating gc
    and allocator thread' (git fixes (block drivers)).

  - Revert commit e918e570415c ('tpm_tis: Remove the HID
    IFX0102') (bsc#1111666).

  - Revert 'dm crypt: use WQ_HIGHPRI for the IO and crypt
    workqueues' (git fixes (block drivers)).

  - Revert 'ipv6: add mtu lock check in
    __ip6_rt_update_pmtu' (networking-stable-20_05_16).

  - Revert pciehp patches that broke booting (bsc#1174887)

  - Revert 'thermal: mediatek: fix register index error'
    (bsc#1111666).

  - Revert 'tools lib traceevent: Remove unneeded qsort and
    uses memmove'

  - rtnetlink: Fix memory(net_device) leak when ->newlink
    fails (git-fixes).

  - s390/bpf: Maintain 8-byte stack alignment (bsc#1169194).

  - s390: fix syscall_get_error for compat processes
    (git-fixes).

  - s390/qdio: consistently restore the IRQ handler
    (git-fixes).

  - s390/qdio: lock device while installing IRQ handler
    (git-fixes).

  - s390/qdio: put thinint indicator after early error
    (git-fixes).

  - s390/qdio: tear down thinint indicator after early error
    (git-fixes).

  - s390/qeth: fix error handling for isolation mode cmds
    (git-fixes).

  - sch_choke: avoid potential panic in choke_reset()
    (networking-stable-20_05_12).

  - sch_sfq: validate silly quantum values
    (networking-stable-20_05_12).

  - scripts/git_sort/git_sort.py: add
    bluetooth/bluetooth-next.git repository

  - scsi: aacraid: fix a signedness bug (bsc#1174296).

  - scsi: hisi_sas: fix calls to dma_set_mask_and_coherent()
    (bsc#1174296).

  - scsi: ibmvscsi: Do not send host info in adapter info
    MAD after LPM (bsc#1172759 ltc#184814).

  - scsi: lpfc: Add an internal trace log buffer
    (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Add blk_io_poll support for latency
    improvment (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Add support to display if adapter dumps are
    available (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Allow applications to issue Common Set
    Features mailbox command (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Avoid another null dereference in
    lpfc_sli4_hba_unset() (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix inconsistent indenting (bsc#1158983).

  - scsi: lpfc: Fix interrupt assignments when multiple
    vectors are supported on same CPU (bsc#1158983).

  - scsi: lpfc: Fix kdump hang on PPC (bsc#1172687
    bsc#1171530).

  - scsi: lpfc: Fix language in 0373 message to reflect
    non-error message (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix less-than-zero comparison of unsigned
    value (bsc#1158983).

  - scsi: lpfc: Fix missing MDS functionality (bsc#1172687
    bsc#1171530).

  - scsi: lpfc: Fix NVMe rport deregister and registration
    during ADISC (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix oops due to overrun when reading SLI3
    data (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix shost refcount mismatch when deleting
    vport (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix stack trace seen while setting rrq
    active (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix unused assignment in
    lpfc_sli4_bsg_link_diag_test (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Update lpfc version to 12.8.0.2
    (bsc#1158983).

  - scsi: megaraid_sas: Fix a compilation warning
    (bsc#1174296).

  - scsi: mpt3sas: Fix double free in attach error handling
    (bsc#1174296).

  - scsi: qedf: Add port_id getter (bsc#1150660).

  - scsi: qla2xxx: Fix a condition in
    qla2x00_find_all_fabric_devs() (bsc#1174296).

  - scsi: qla2xxx: Set NVMe status code for failed NVMe FCP
    request (bsc#1158983).

  - sctp: Do not add the shutdown timer if its already been
    added (networking-stable-20_05_27).

  - sctp: Start shutdown on association restart if in
    SHUTDOWN-SENT state and socket is closed
    (networking-stable-20_05_27).

  - spi: dw: use 'smp_mb()' to avoid sending spi data error
    (bsc#1051510).

  - spi: fix initial SPI_SR value in spi-fsl-dspi
    (bsc#1111666).

  - spi: pxa2xx: Apply CS clk quirk to BXT (bsc#1111666).

  - spi: spidev: fix a race between spidev_release and
    spidev_remove (bsc#1111666).

  - spi: spi-mem: Fix Dual/Quad modes on Octal-capable
    devices (bsc#1111666).

  - spi: spi-sun6i: sun6i_spi_transfer_one(): fix setting of
    clock rate (bsc#1111666).

  - staging: comedi: verify array index is correct before
    using it (bsc#1111666).

  - staging: rtl8712: Fix
    IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK (bsc#1051510).

  - staging: sm750fb: add missing case while setting
    FB_VISUAL (bsc#1051510).

  - SUNRPC: The TCP back channel mustn't disappear while
    requests are outstanding (bsc#1152624).

  - tg3: driver sleeps indefinitely when EEH errors exceed
    eeh_max_freezes (bsc#1173284).

  - timers: Add a function to start/reduce a timer
    (networking-stable-20_05_27).

  - tpm_tis: extra chip->ops check on error path in
    tpm_tis_core_init (bsc#1111666).

  - tpm_tis: Remove the HID IFX0102 (bsc#1111666).

  - tracing: Fix event trigger to accept redundant spaces
    (git-fixes).

  - tty: hvc_console, fix crashes on parallel open/close
    (git-fixes).

  - tty: n_gsm: Fix bogus i++ in gsm_data_kick
    (bsc#1051510).

  - tty: n_gsm: Fix SOF skipping (bsc#1051510).

  - tty: n_gsm: Fix waking up upper tty layer when room
    available (bsc#1051510).

  - tunnel: Propagate ECT(1) when decapsulating as
    recommended by RFC6040 (networking-stable-20_05_12).

  - ubifs: remove broken lazytime support (bsc#1173826).

  - usb: add USB_QUIRK_DELAY_INIT for Logitech C922
    (git-fixes).

  - usb: c67x00: fix use after free in c67x00_giveback_urb
    (bsc#1111666).

  - usb: chipidea: core: add wakeup support for extcon
    (bsc#1111666).

  - usb: dwc2: Fix shutdown callback in platform
    (bsc#1111666).

  - usb: dwc2: gadget: move gadget resume after the core is
    in L0 state (bsc#1051510).

  - usb: dwc3: gadget: introduce cancelled_list (git-fixes).

  - usb: dwc3: gadget: never call ->complete() from
    ->ep_queue() (git-fixes).

  - usb: dwc3: gadget: Properly handle ClearFeature(halt)
    (git-fixes).

  - usb: dwc3: gadget: Properly handle failed kick_transfer
    (git-fixes).

  - usb: ehci: reopen solution for Synopsys HC bug
    (git-fixes).

  - usb: gadget: fix potential double-free in m66592_probe
    (bsc#1111666).

  - usb: gadget: lpc32xx_udc: do not dereference ep pointer
    before null check (bsc#1051510).

  - usb: gadget: udc: atmel: fix uninitialized read in debug
    printk (bsc#1111666).

  - usb: gadget: udc: atmel: remove outdated comment in
    usba_ep_disable() (bsc#1111666).

  - usb: gadget: udc: Potential Oops in error handling code
    (bsc#1111666).

  - usb: gadget: udc: s3c2410_udc: Remove pointless NULL
    check in s3c2410_udc_nuke (bsc#1051510).

  - usb: host: ehci-exynos: Fix error check in
    exynos_ehci_probe() (bsc#1111666).

  - usb: host: ehci-mxc: Add error handling in
    ehci_mxc_drv_probe() (bsc#1051510).

  - usb: musb: Fix runtime PM imbalance on error
    (bsc#1051510).

  - usb: musb: start session in resume for host port
    (bsc#1051510).

  - usbnet: smsc95xx: Fix use-after-free after removal
    (bsc#1111666).

  - usb: ohci-sm501: Add missed iounmap() in remove
    (bsc#1111666).

  - usb: serial: ch341: add new Product ID for CH340
    (bsc#1111666).

  - usb: serial: cypress_m8: enable Simply Automated UPB PIM
    (bsc#1111666).

  - usb: serial: iuu_phoenix: fix memory corruption
    (bsc#1111666).

  - usb: serial: option: add GosunCn GM500 series
    (bsc#1111666).

  - usb: serial: option: add Quectel EG95 LTE modem
    (bsc#1111666).

  - usb: serial: option: add Telit LE910C1-EUX compositions
    (bsc#1051510).

  - usb: serial: qcserial: add DW5816e QDL support
    (bsc#1051510).

  - usb: serial: usb_wwan: do not resubmit rx urb on fatal
    errors (bsc#1051510).

  - usb: serial: usb_wwan: do not resubmit rx urb on fatal
    errors (git-fixes).

  - vfio/pci: Fix SR-IOV VF handling with MMIO blocking
    (bsc#1174123).

  - vfs: Fix EOVERFLOW testing in put_compat_statfs64
    (bnc#1151927 5.3.6).

  - virtio-blk: handle block_device_operations callbacks
    after hot unplug (git fixes (block drivers)).

  - virtio: virtio_console: add missing
    MODULE_DEVICE_TABLE() for rproc serial (git-fixes).

  - vmxnet3: add geneve and vxlan tunnel offload support
    (bsc#1172484).

  - vmxnet3: add support to get/set rx flow hash
    (bsc#1172484).

  - vmxnet3: allow rx flow hash ops only when rss is enabled
    (bsc#1172484).

  - vmxnet3: avoid format strint overflow warning
    (bsc#1172484).

  - vmxnet3: prepare for version 4 changes (bsc#1172484).

  - vmxnet3: Remove always false conditional statement
    (bsc#1172484).

  - vmxnet3: remove redundant initialization of pointer 'rq'
    (bsc#1172484).

  - vmxnet3: remove unused flag 'rxcsum' from struct
    vmxnet3_adapter (bsc#1172484).

  - vmxnet3: Replace msleep(1) with usleep_range()
    (bsc#1172484).

  - vmxnet3: update to version 4 (bsc#1172484).

  - vmxnet3: use correct hdr reference when packet is
    encapsulated (bsc#1172484).

  - vsock: fix timeout in vsock_accept()
    (networking-stable-20_06_07).

  - vt_compat_ioctl(): clean up, use compat_ptr() properly
    (git-fixes).

  - vxlan: Avoid infinite loop when suppressing NS messages
    with invalid options (git-fixes).

  - w1: omap-hdq: cleanup to add missing newline for some
    dev_dbg (bsc#1051510).

  - watchdog: sp805: fix restart handler (bsc#1111666).

  - wil6210: add general initialization/size checks
    (bsc#1111666).

  - wil6210: check rx_buff_mgmt before accessing it
    (bsc#1111666).

  - wil6210: ignore HALP ICR if already handled
    (bsc#1111666).

  - wil6210: make sure Rx ring sizes are correlated
    (git-fixes).

  - work around mvfs bug (bsc#1162063).

  - x86/apic: Install an empty physflat_init_apic_ldr
    (bsc#1163309).

  - x86/cpu/amd: Make erratum #1054 a legacy erratum
    (bsc#1114279).

  - x86/events/intel/ds: Add PERF_SAMPLE_PERIOD into
    PEBS_FREERUNNING_FLAGS (git-fixes).

  - x86: Fix early boot crash on gcc-10, third try
    (bsc#1114279).

  - x86/(mce,mm): Unmap the entire page if the whole page is
    affected and poisoned (bsc#1172257).

  - x86/reboot/quirks: Add MacBook6,1 reboot quirk
    (bsc#1114279).

  - xfrm: fix error in comment (git fixes).

  - xhci: Fix enumeration issue when setting max packet size
    for FS devices (git-fixes).

  - xhci: Fix incorrect EP_STATE_MASK (git-fixes).

  - vt: vt_ioctl: remove unnecessary console allocation
    checks (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085030"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170442"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174887"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.59.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.59.1") ) flag++;

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
