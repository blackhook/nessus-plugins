#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-826.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111590);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-18344", "CVE-2018-5390");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-826)");
  script_summary(english:"Check for the openSUSE-2018-826 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.0 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2018-5390 aka 'SegmentSmack': A remote attacker even
    with relatively low bandwidth could have caused lots of
    CPU usage by triggering the worst case scenario during
    IP and/or TCP fragment reassembly (bsc#1102340)

  - CVE-2017-18344: The timer_create syscall implementation
    in kernel/time/posix-timers.c in the Linux kernel
    doesn't properly validate the sigevent->sigev_notify
    field, which leads to out-of-bounds access in the
    show_timer function (called when /proc/$PID/timers is
    read). This allowed userspace applications to read
    arbitrary kernel memory (on a kernel built with
    CONFIG_POSIX_TIMERS and CONFIG_CHECKPOINT_RESTORE)
    (bnc#1102851).

The following non-security bugs were fixed :

  - acpi, APEI, EINJ: Subtract any matching Register Region
    from Trigger resources (bsc#1051510).

  - acpi/nfit: fix cmd_rc for acpi_nfit_ctl to always return
    a value (bsc#1051510).

  - acpi, nfit: Fix scrub idle detection (bsc#1094119).

  - acpi / processor: Finish making
    acpi_processor_ppc_has_changed() void (bsc#1051510).

  - ahci: Disable LPM on Lenovo 50 series laptops with a too
    old BIOS (bsc#1051510).

  - alsa: emu10k1: add error handling for snd_ctl_add
    (bsc#1051510).

  - alsa: emu10k1: Rate-limit error messages about page
    errors (bsc#1051510).

  - alsa: fm801: add error handling for snd_ctl_add
    (bsc#1051510).

  - alsa: hda: add mute led support for HP ProBook 455 G5
    (bsc#1051510).

  - alsa: hda - Handle pm failure during hotplug
    (bsc#1051510).

  - alsa: hda/realtek - Add Panasonic CF-SZ6 headset jack
    quirk (bsc#1051510).

  - alsa: hda/realtek - two more lenovo models need fixup of
    MIC_LOCATION (bsc#1051510).

  - alsa: hda/realtek - Yet another Clevo P950 quirk entry
    (bsc#1101143).

  - alsa: rawmidi: Change resized buffers atomically
    (bsc#1051510).

  - alsa: usb-audio: Apply rate limit to warning messages in
    URB complete callback (bsc#1051510).

  - alx: take rtnl before calling __alx_open from resume
    (bsc#1051510).

  - arm64: Correct type for PUD macros (bsc#1103723).

  - arm64: Disable unhandled signal log messages by default
    (bsc#1103724).

  - arm64: kpti: Use early_param for kpti= command-line
    option (bsc#1103220).

  - arm64: KVM: fix VTTBR_BADDR_MASK BUG_ON off-by-one
    (bsc#1103725).

  - arm64: mm: Fix set_memory_valid() declaration
    (bsc#1103726).

  - arm64: perf: correct PMUVer probing (bsc#1103727).

  - arm64: ptrace: Avoid setting compat FPR to garbage if
    get_user fails (bsc#1103728).

  - arm64: spinlock: Fix theoretical trylock() A-B-A with
    LSE atomics (bsc#1103729).

  - arm64: vdso: fix clock_getres for 4GiB-aligned res
    (bsc#1103730).

  - arm: module: fix modsign build error (bsc#1093666).

  - ASoC: dpcm: fix BE dai not hw_free and shutdown
    (bsc#1051510).

  - ASoC: mediatek: preallocate pages use platform device
    (bsc#1051510).

  - ASoC: topology: Add missing clock gating parameter when
    parsing hw_configs (bsc#1051510).

  - ASoC: topology: Fix bclk and fsync inversion in
    set_link_hw_format() (bsc#1051510).

  - ath9k_htc: Add a sanity check in
    ath9k_htc_ampdu_action() (bsc#1051510).

  - ath: Add regulatory mapping for APL13_WORLD
    (bsc#1051510).

  - ath: Add regulatory mapping for APL2_FCCA (bsc#1051510).

  - ath: Add regulatory mapping for Bahamas (bsc#1051510).

  - ath: Add regulatory mapping for Bermuda (bsc#1051510).

  - ath: Add regulatory mapping for ETSI8_WORLD
    (bsc#1051510).

  - ath: Add regulatory mapping for FCC3_ETSIC
    (bsc#1051510).

  - ath: Add regulatory mapping for Serbia (bsc#1051510).

  - ath: Add regulatory mapping for Tanzania (bsc#1051510).

  - ath: Add regulatory mapping for Uganda (bsc#1051510).

  - atl1c: reserve min skb headroom (bsc#1051510).

  - audit: ensure that 'audit=1' actually enables audit for
    PID 1 (bsc#1051510).

  - audit: Fix wrong task in comparison of session ID
    (bsc#1051510).

  - audit: return on memory error to avoid NULL pointer
    dereference (bsc#1051510).

  - b44: Initialize 64-bit stats seqcount (bsc#1051510).

  - backlight: as3711_bl: Fix Device Tree node leaks
    (bsc#1051510).

  - backlight: lm3630a: Bump REG_MAX value to 0x50 instead
    of 0x1F (bsc#1051510).

  - backlight: pwm_bl: Do not use GPIOF_* with
    gpiod_get_direction (bsc#1051510).

  - batman-adv: Accept only filled wifi station info
    (bsc#1051510).

  - batman-adv: Always initialize fragment header priority
    (bsc#1051510).

  - batman-adv: Avoid race in TT TVLV allocator helper
    (bsc#1051510).

  - batman-adv: Avoid storing non-TT-sync flags on singular
    entries too (bsc#1051510).

  - batman-adv: Fix bat_ogm_iv best gw refcnt after netlink
    dump (bsc#1051510).

  - batman-adv: Fix bat_v best gw refcnt after netlink dump
    (bsc#1051510).

  - batman-adv: Fix check of retrieved orig_gw in
    batadv_v_gw_is_eligible (bsc#1051510).

  - batman-adv: Fix debugfs path for renamed hardif
    (bsc#1051510).

  - batman-adv: Fix debugfs path for renamed softif
    (bsc#1051510).

  - batman-adv: fix header size check in batadv_dbg_arp()
    (bsc#1051510).

  - batman-adv: Fix internal interface indices types
    (bsc#1051510).

  - batman-adv: Fix lock for ogm cnt access in
    batadv_iv_ogm_calc_tq (bsc#1051510).

  - batman-adv: Fix multicast packet loss with a single
    WANT_ALL_IPV4/6 flag (bsc#1051510).

  - batman-adv: fix multicast-via-unicast transmission with
    AP isolation (bsc#1051510).

  - batman-adv: Fix netlink dumping of BLA backbones
    (bsc#1051510).

  - batman-adv: Fix netlink dumping of BLA claims
    (bsc#1051510).

  - batman-adv: fix packet checksum in receive path
    (bsc#1051510).

  - batman-adv: fix packet loss for broadcasted DHCP packets
    to a server (bsc#1051510).

  - batman-adv: Fix skbuff rcsum on packet reroute
    (bsc#1051510).

  - batman-adv: fix TT sync flag inconsistencies
    (bsc#1051510).

  - batman-adv: Fix TT sync flags for intermediate TT
    responses (bsc#1051510).

  - batman-adv: Ignore invalid batadv_iv_gw during netlink
    send (bsc#1051510).

  - batman-adv: Ignore invalid batadv_v_gw during netlink
    send (bsc#1051510).

  - batman-adv: invalidate checksum on fragment reassembly
    (bsc#1051510).

  - batman-adv: update data pointers after skb_cow()
    (bsc#1051510).

  - batman-adv: Use default throughput value on cfg80211
    error (bsc#1051510).

  - blk-mq: count allocated but not started requests in
    iostats inflight (bsc#1077989).

  - blk-mq: fix sysfs inflight counter (bsc#1077989).

  - block: always set partition number to '0' in
    blk_partition_remap() (bsc#1054245).

  - block: always set partition number to '0' in
    blk_partition_remap() (bsc#1077989).

  - block: bio_check_eod() needs to consider partitions
    (bsc#1077989).

  - block: fail op_is_write() requests to read-only
    partitions (bsc#1077989).

  - block: pass 'run_queue' to blk_mq_request_bypass_insert
    (bsc#1077989).

  - block: set request_list for request (bsc#1077989).

  - bluetooth: avoid recursive locking in
    hci_send_to_channel() (bsc#1051510).

  - bluetooth: btusb: Add a new Realtek 8723DE ID 2ff8:b011
    (bsc#1051510).

  - bluetooth: btusb: add ID for LiteOn 04ca:301a
    (bsc#1051510).

  - bluetooth: hci_ll: Add support for the external clock
    (bsc#1051510).

  - bluetooth: hci_ll: Fix download_firmware() return when
    __hci_cmd_sync fails (bsc#1051510).

  - bluetooth: hci_nokia: select BT_HCIUART_H4
    (bsc#1051510).

  - bluetooth: hci_qca: Fix 'Sleep inside atomic section'
    warning (bsc#1051510).

  - bluetooth: hci_uart: fix kconfig dependency
    (bsc#1051510).

  - bnxt_en: Always set output parameters in
    bnxt_get_max_rings() (bsc#1050242).

  - bnxt_en: Do not modify max IRQ count after rdma driver
    requests/frees IRQs (bsc#1050242).

  - bnxt_en: Fix for system hang if request_irq fails
    (bsc#1050242 ).

  - bnxt_en: Fix inconsistent BNXT_FLAG_AGG_RINGS logic
    (bsc#1050242 ).

  - bnxt_en: Fix the vlan_tci exact match check (bsc#1050242
    ).

  - bonding: re-evaluate force_primary when the primary
    slave name changes (networking-stable-18_06_20).

  - brcmfmac: Add support for bcm43364 wireless chipset
    (bsc#1051510).

  - btrfs: Do not remove block group still has pinned down
    bytes (bsc#1086457).

  - bus: arm-cci: Fix use of smp_processor_id() in
    preemptible context (bsc#1051510).

  - bus: arm-ccn: Check memory allocation failure
    (bsc#1051510).

  - bus: arm-ccn: fix module unloading Error: Removing state
    147 which has instances left (bsc#1051510).

  - bus: arm-ccn: Fix use of smp_processor_id() in
    preemptible context (bsc#1051510).

  - can: bcm: check for null sk before deferencing it via
    the call to sock_net (bsc#1051510).

  - can: m_can.c: fix setup of CCCR register: clear CCCR
    NISO bit before checking can.ctrlmode (bsc#1051510).

  - can: mpc5xxx_can: check of_iomap return before use
    (bsc#1051510).

  - can: peak_canfd: fix firmware < v3.3.0: limit allocation
    to 32-bit DMA addr only (bsc#1051510).

  - can: xilinx_can: fix device dropping off bus on RX
    overrun (bsc#1051510).

  - can: xilinx_can: fix incorrect clear of non-processed
    interrupts (bsc#1051510).

  - can: xilinx_can: fix power management handling
    (bsc#1051510).

  - can: xilinx_can: fix recovery from error states not
    being propagated (bsc#1051510).

  - can: xilinx_can: fix RX loop if RXNEMP is asserted
    without RXOK (bsc#1051510).

  - can: xilinx_can: fix RX overflow interrupt not being
    enabled (bsc#1051510).

  - can: xilinx_can: keep only 1-2 frames in TX FIFO to fix
    TX accounting (bsc#1051510).

  - cdc_ncm: avoid padding beyond end of skb
    (networking-stable-18_06_20).

  - cfg80211: initialize sinfo in cfg80211_get_station
    (bsc#1051510).

  - checkpatch: add 6 missing types to --list-types
    (bsc#1051510).

  - cifs: do not allow creating sockets except with SMB1
    posix exensions (bsc#1102097).

  - cifs: Fix infinite loop when using hard mount option
    (bsc#1091171).

  - clk: at91: fix clk-generated parenting (bsc#1051510).

  - clk: at91: PLL recalc_rate() now using cached MUL and
    DIV values (bsc#1051510).

  - clk: axi-clkgen: Correctly handle nocount bit in
    recalc_rate() (bsc#1051510).

  - clk: bcm2835: De-assert/assert PLL reset signal when
    appropriate (bsc#1051510).

  - clk: Do not show the incorrect clock phase
    (bsc#1051510).

  - clk: Do not write error code into divider register
    (bsc#1051510).

  - clk: fix false-positive Wmaybe-uninitialized warning
    (bsc#1051510).

  - clk: fix mux clock documentation (bsc#1051510).

  - clk: Fix __set_clk_rates error print-string
    (bsc#1051510).

  - clk: fix set_rate_range when current rate is out of
    range (bsc#1051510).

  - clk: hi3660: fix incorrect uart3 clock freqency
    (bsc#1051510).

  - clk: hi6220: change watchdog clock source (bsc#1051510).

  - clk: hi6220: mark clock cs_atb_syspll as critical
    (bsc#1051510).

  - clk: hisilicon: fix potential NULL dereference in
    hisi_clk_alloc() (bsc#1051510).

  - clk: hisilicon: mark wdt_mux_p[] as const (bsc#1051510).

  - clk: honor CLK_MUX_ROUND_CLOSEST in generic clk mux
    (bsc#1051510).

  - clk: imx6: refine hdmi_isfr's parent to make HDMI work
    on i.MX6 SoCs w/o VPU (bsc#1051510).

  - clk: imx7d: fix mipi dphy div parent (bsc#1051510).

  - clk: mediatek: add the option for determining PLL source
    clock (bsc#1051510).

  - clk: mediatek: mark mtk_infrasys_init_early __init
    (bsc#1051510).

  - clk: meson: gxbb: fix clk_mclk_i958 divider flags
    (bsc#1051510).

  - clk: meson: gxbb: fix meson cts_amclk divider flags
    (bsc#1051510).

  - clk: meson: gxbb: fix wrong clock for SARADC/SANA
    (bsc#1051510).

  - clk: meson: meson8b: fix protection against undefined
    clks (bsc#1051510).

  - clk: meson: mpll: fix mpll0 fractional part ignored
    (bsc#1051510).

  - clk: meson: mpll: use 64-bit maths in params_from_rate
    (bsc#1051510).

  - clk: meson: remove unnecessary rounding in the pll clock
    (bsc#1051510).

  - clk: mvebu: use correct bit for 98DX3236 NAND
    (bsc#1051510).

  - clk: qcom: Base rcg parent rate off plan frequency
    (bsc#1051510).

  - clk: qcom: clk-smd-rpm: Fix the reported rate of
    branches (bsc#1051510).

  - clk: qcom: common: fix legacy board-clock registration
    (bsc#1051510).

  - clk: qcom: msm8916: Fix bimc gpu clock ops
    (bsc#1051510).

  - clk: qcom: msm8916: fix mnd_width for codec_digcodec
    (bsc#1051510).

  - clk: renesas: div6: Document fields used for parent
    selection (bsc#1051510).

  - clk: renesas: r8a7745: Remove nonexisting scu-src[0789]
    clocks (bsc#1051510).

  - clk: renesas: r8a7745: Remove PLL configs for MD19=0
    (bsc#1051510).

  - clk: renesas: r8a7795: Correct pwm, gpio, and i2c parent
    clocks on ES2.0 (bsc#1051510).

  - clk: renesas: rcar-gen2: Fix PLL0 on R-Car V2H and E2
    (bsc#1051510).

  - clk: rockchip: Fix wrong parent for SDMMC phase clock
    for rk3228 (bsc#1051510).

  - clk: rockchip: Prevent calculating mmc phase if clock
    rate is zero (bsc#1051510).

  - clk: samsung: exynos3250: Fix PLL rates (bsc#1051510).

  - clk: samsung: exynos5250: Add missing clocks for FIMC
    LITE SYSMMU devices (bsc#1051510).

  - clk: samsung: exynos5250: Fix PLL rates (bsc#1051510).

  - clk: samsung: exynos5260: Fix PLL rates (bsc#1051510).

  - clk: samsung: exynos5433: Fix PLL rates (bsc#1051510).

  - clk: samsung: exynos7: Fix PLL rates (bsc#1051510).

  - clk: samsung: Fix m2m scaler clock on Exynos542x
    (bsc#1051510).

  - clk: samsung: s3c2410: Fix PLL rates (bsc#1051510).

  - clk: scpi: error when clock fails to register
    (bsc#1051510).

  - clk: scpi: fix return type of __scpi_dvfs_round_rate
    (bsc#1051510).

  - clk: si5351: fix PLL reset (bsc#1051510).

  - clk: si5351: Rename internal plls to avoid name
    collisions (bsc#1051510).

  - clk: socfpga: Fix the smplsel on Arria10 and Stratix10
    (bsc#1051510).

  - clk: sunxi: fix build warning (bsc#1051510).

  - clk: sunxi: fix uninitialized access (bsc#1051510).

  - clk: sunxi-ng: a31: Fix CLK_OUT_* clock ops
    (bsc#1051510).

  - clk: sunxi-ng: add CLK_SET_RATE_PARENT flag to H3 GPU
    clock (bsc#1051510).

  - clk: sunxi-ng: add CLK_SET_RATE_UNGATE to all H3 PLLs
    (bsc#1051510).

  - clk: sunxi-ng: allow set parent clock (PLL_CPUX) for
    CPUX clock on H3 (bsc#1051510).

  - clk: sunxi-ng: Fix fractional mode for N-M clocks
    (bsc#1051510).

  - clk: sunxi-ng: h3: gate then ungate PLL CPU clk after
    rate change (bsc#1051510).

  - clk: sunxi-ng: Make fractional helper less chatty
    (bsc#1051510).

  - clk: sunxi-ng: multiplier: Fix fractional mode
    (bsc#1051510).

  - clk: sunxi-ng: nm: Check if requested rate is supported
    by fractional clock (bsc#1051510).

  - clk: sunxi-ng: sun5i: Fix bit offset of audio PLL
    post-divider (bsc#1051510).

  - clk: sunxi-ng: sun6i: Export video PLLs (bsc#1051510).

  - clk: sunxi-ng: sun6i: Rename HDMI DDC clock to avoid
    name collision (bsc#1051510).

  - clk: sunxi-ng: Wait for lock when using fractional mode
    (bsc#1051510).

  - clk: tegra: Fix cclk_lp divisor register (bsc#1051510).

  - clk: tegra: Fix pll_u rate configuration (bsc#1051510).

  - clk: tegra: Use readl_relaxed_poll_timeout_atomic() in
    tegra210_clock_init() (bsc#1051510).

  - clk: ti: dra7-atl-clock: fix child-node lookups
    (bsc#1051510).

  - clk: uniphier: fix DAPLL2 clock rate of Pro5
    (bsc#1051510).

  - clk: x86: Do not gate clocks enabled by the firmware
    (bsc#1051510).

  - clockevents/drivers/cs5535: Improve resilience to
    spurious interrupts (bsc#1051510).

  - clocksource/drivers/stm32: Fix kernel panic with
    multiple timers (bsc#1051510).

  - cnic: Fix an error handling path in
    'cnic_alloc_bnx2x_resc()' (bsc#1086324).

  - cpufreq: cppc_cpufreq: Fix cppc_cpufreq_init() failure
    path (bsc#1100884).

  - cpufreq: CPPC: Initialize shared perf capabilities of
    CPUs (bsc#1100884).

  - cpufreq: docs: Add missing cpuinfo_cur_freq description
    (bsc#1051510).

  - cpufreq: docs: Drop intel-pstate.txt from index.txt
    (bsc#1051510).

  - cpufreq: Fix new policy initialization during limits
    updates via sysfs (bsc#1100884).

  - cpufreq: governors: Fix long idle detection logic in
    load calculation (bsc#1100884).

  - cpufreq: intel_pstate: Limit the scope of HWP dynamic
    boost platforms (bsc#1066110).

  - cpufreq: powernv: Fix hardlockup due to synchronous
    smp_call in timer interrupt (bsc#1100884).

  - cpuidle: powernv: Fix promotion from snooze if next
    state disabled (bsc#1100884).

  - crash_dump: is_kdump_kernel can be boolean
    (bsc#1103230).

  - crypto: caam/qi - explicitly set dma_ops (bsc#1051510).

  - crypto: ccp - remove unused variable qim (bsc#1051510).

  - crypto: change transient busy return code to -ENOSPC
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - crypto: chelsio - Add authenc versions of ctr and sha
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - crypto: chelsio - Check error code with IS_ERR macro
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - crypto: chelsio - check for sg null (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - crypto: chelsio - do not leak pointers to authenc keys
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - crypto: chelsio - Fix an error code in
    chcr_hash_dma_map() (bsc#1097585 bsc#1097586 bsc#1097587
    bsc#1097588 bsc#1097583 bsc#1097584).

  - crypto: chelsio - Fix Indentation (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - crypto: chelsio - Fix indentation warning (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - crypto: chelsio - Fix iv passed in fallback path for
    rfc3686 (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - crypto: chelsio - Fix IV updated in XTS operation
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - crypto: chelsio - Fix src buffer dma length (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - crypto: chelsio - Make function aead_ccm_validate_input
    static (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - crypto: chelsio - Move DMA un/mapping to chcr from lld
    cxgb4 driver (bsc#1097585 bsc#1097586 bsc#1097587
    bsc#1097588 bsc#1097583 bsc#1097584).

  - crypto: chelsio - Remove allocation of sg list to
    implement 2K limit of dsgl header (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - crypto: chelsio - Remove dst sg size zero check
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - crypto: chelsio - Remove unused parameter (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - crypto: chelsio - Update IV before sending request to HW
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - crypto: chelsio - Use kernel round function to align
    lengths (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - crypto: chelsio - Use x8_ble gf multiplication to
    calculate IV (bsc#1097585 bsc#1097586 bsc#1097587
    bsc#1097588 bsc#1097583 bsc#1097584).

  - crypto: crypto4xx - fix crypto4xx_build_pdr,
    crypto4xx_build_sdr leak (bsc#1051510).

  - crypto: crypto4xx - remove bad list_del (bsc#1051510).

  - crypto: gf128mul - The x8_ble multiplication functions
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - crypto: sha512-mb - add some missing unlock on error
    (bsc#1051510).

  - cxgb4: Add FORCE_PAUSE bit to 32 bit port caps
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: Add HMA support (bsc#1097585 bsc#1097586
    bsc#1097587 bsc#1097588 bsc#1097583 bsc#1097584).

  - cxgb4: Add new T5 device id (bsc#1097585 bsc#1097586
    bsc#1097587 bsc#1097588 bsc#1097583 bsc#1097584).

  - cxgb4: add new T5 device id's (bsc#1097585 bsc#1097586
    bsc#1097587 bsc#1097588 bsc#1097583 bsc#1097584).

  - cxgb4: Add new T6 device ids (bsc#1097585 bsc#1097586
    bsc#1097587 bsc#1097588 bsc#1097583 bsc#1097584).

  - cxgb4: Adds CPL support for Shared Receive Queues
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: Add support for ethtool i2c dump (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: Add support to initialise/read SRQ entries
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: Add support to query HW SRQ parameters
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: Add TP Congestion map entry for single-port
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: avoid schedule while atomic (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: change the port capability bits definition
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: Check alignment constraint for T6 (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: Check for kvzalloc allocation failure
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: clean up init_one (bsc#1097585 bsc#1097586
    bsc#1097587 bsc#1097588 bsc#1097583 bsc#1097584).

  - cxgb4: collect hardware dump in second kernel
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: collect SGE PF/VF queue map (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: copy adap index to PF0-3 adapter instances
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: copy mbox log size to PF0-3 adap instances
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: copy the length of cpl_tx_pkt_core to fw_wr
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: copy vlan_id in ndo_get_vf_config (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4/cxgb4vf: add support for ndo_set_vf_vlan
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4/cxgb4vf: check fw caps to set link mode mask
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4/cxgb4vf: link management changes for new SFP
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4/cxgb4vf: Notify link changes to OS-dependent code
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: depend on firmware event for link status
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: do L1 config when module is inserted (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: do not display 50Gbps as unsupported speed
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: do not fail vf instatiation in slave mode
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: do not set needs_free_netdev for mgmt dev's
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: enable inner header checksum calculation
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: enable ZLIB_DEFLATE when building cxgb4
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: Fix error handling path in 'init_one()'
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: Fix queue free path of ULD drivers (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: fix the wrong conversion of Mbps to Kbps
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: Fix {vxlan/geneve}_port initialization
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: free up resources of pf 0-3 (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: increase max tx rate limit to 100 Gbps
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: IPv6 filter takes 2 tids (bsc#1097585 bsc#1097586
    bsc#1097587 bsc#1097588 bsc#1097583 bsc#1097584).

  - cxgb4: notify fatal error to uld drivers (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: remove dead code when allocating filter
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: restructure VF mgmt code (bsc#1097585 bsc#1097586
    bsc#1097587 bsc#1097588 bsc#1097583 bsc#1097584).

  - cxgb4: rework on-chip memory read (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: Setup FW queues before registering netdev
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: Support firmware rdma write completion work
    request (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: Support firmware rdma write with immediate work
    request (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: support new ISSI flash parts (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: update dump collection logic to use compression
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: update latest firmware version supported
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: update latest firmware version supported
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: update LE-TCAM collection for T6 (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: use CLIP with LIP6 on T6 for TCAM filters
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: use zlib deflate to compress firmware dump
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4vf: display pause settings (bsc#1097585 bsc#1097586
    bsc#1097587 bsc#1097588 bsc#1097583 bsc#1097584).

  - cxgb4vf: Forcefully link up virtual interfaces
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxgb4: zero the HMA memory (bsc#1097585 bsc#1097586
    bsc#1097587 bsc#1097588 bsc#1097583 bsc#1097584).

  - cxgbit: call neigh_event_send() to update MAC address
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - dccp: do not free ccid2_hc_tx_sock struct in
    dccp_disconnect() (networking-stable-18_06_08).

  - device property: Allow iterating over available child
    fwnodes (bsc#1098633).

  - device property: Introduce fwnode_call_bool_op() for ops
    that return bool (bsc#1098633).

  - device property: Introduce fwnode_device_is_available()
    (bsc#1098633).

  - device property: Introduce fwnode_get_mac_address()
    (bsc#1098633).

  - device property: Introduce fwnode_get_phy_mode()
    (bsc#1098633).

  - device property: Introduce fwnode_irq_get()
    (bsc#1098633).

  - device property: Move fwnode graph ops to firmware
    specific locations (bsc#1098633).

  - device property: Move FW type specific functionality to
    FW specific files (bsc#1098633).

  - device property: preserve usecount for node passed to
    of_fwnode_graph_get_port_parent() (bsc#1098633).

  - dmaengine: fsl-edma: disable clks on all error paths
    (bsc#1051510).

  - dmaengine: k3dma: Off by one in k3_of_dma_simple_xlate()
    (bsc#1051510).

  - dmaengine: mv_xor_v2: Fix clock resource by adding a
    register clock (bsc#1051510).

  - dmaengine: omap-dma: port_window support correction for
    both direction (bsc#1051510).

  - dmaengine: pl330: fix a race condition in case of
    threaded irqs (bsc#1051510).

  - dmaengine: pl330: report BURST residue granularity
    (bsc#1051510).

  - dmaengine: qcom: bam_dma: get num-channels and num-ees
    from dt (bsc#1051510).

  - dmaengine: qcom_hidma: check pending interrupts
    (bsc#1051510).

  - dmaengine: rcar-dmac: Check the done lists in
    rcar_dmac_chan_get_residue() (bsc#1051510).

  - dmaengine: rcar-dmac: fix max_chunk_size for R-Car Gen3
    (bsc#1051510).

  - dmaengine: tegra210-adma: fix of_irq_get() error check
    (bsc#1051510).

  - dmaengine: tegra-apb: Really fix runtime-pm usage
    (bsc#1051510).

  - dmaengine: xilinx_dma: Fix error code format specifier
    (bsc#1051510).

  - dmaengine: zynqmp_dma: Fix race condition in the probe
    (bsc#1051510).

  - doc: Rename .system_keyring to .builtin_trusted_keys
    (bsc#1051510).

  - doc: SKB_GSO_[IPIP|SIT] have been replaced
    (bsc#1051510).

  - docs-rst: fix broken links to dynamic-debug-howto in
    kernel-parameters (bsc#1051510).

  - docs: segmentation-offloads.txt: Fix ref to
    SKB_GSO_TUNNEL_REMCSUM (bsc#1051510).

  - documentation: admin-guide: intel_pstate: Fix sysfs path
    (bsc#1051510).

  - dp83640: Ensure against premature access to PHY
    registers after reset (bsc#1051510).

  - drbd: fix access after free (bsc#1051510).

  - driver core: Fix link to device power management
    documentation (bsc#1051510).

  - driver core: Partially revert 'driver core: correct
    device's shutdown order' (bsc#1051510).

  - drivers/firmware: psci_checker: Add missing
    destroy_timer_on_stack() (bsc#1051510).

  - drivers/net/ethernet/qlogic/qed: Fix __qed_spq_block()
    ordering (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - drivers: net: i40evf: use setup_timer() helper
    (bsc#1101816 ).

  - drivers: soc: sunxi: fix error processing on base
    address when claiming (bsc#1051510).

  - drm: Add DP PSR2 sink enable bit (bsc#1051510).

  - drm/amdgpu: Remove VRAM from shared bo domains
    (bsc#1051510).

  - drm/atomic: Check old_plane_state->crtc in
    drm_atomic_helper_async_check() (bsc#1051510).

  - drm/atomic: Handling the case when setting old crtc for
    plane (bsc#1051510).

  - drm/atomic-helper: Drop plane->fb references only for
    drm_atomic_helper_shutdown() (bsc#1051510).

  - drm/atomic: Initialize variables in
    drm_atomic_helper_async_check() to make gcc happy
    (bsc#1051510).

  - drm/atomic: Make async plane update checks work as
    intended, v2 (bsc#1051510).

  - drm/bridge/sii8620: fix potential buffer overflow
    (bsc#1051510).

  - drm/dp/mst: Fix off-by-one typo when dump payload table
    (bsc#1051510).

  - drm/exynos: Fix dma-buf import (bsc#1051510).

  - drm/gma500: fix psb_intel_lvds_mode_valid()'s return
    type (bsc#1051510).

  - drm/i915/dp: Send DPCD ON for MST before phy_up
    (bsc#1051510).

  - drm/i915: Fix hotplug irq ack on i965/g4x (bsc#1051510).

  - drm/i915: Only call tasklet_kill() on the first
    prepare_reset (bsc#1051510).

  - drm: mali-dp: Uninitialized variable in
    malidp_se_check_scaling() (bsc#1087092).

  - drm/nouveau: Avoid looping through fake MST connectors
    (bsc#1051510).

  - drm/nouveau/drm/nouveau: Fix runtime PM leak in
    nv50_disp_atomic_commit() (bsc#1090888).

  - drm/nouveau/fifo/gk104-: poll for runlist update
    completion (bsc#1051510).

  - drm/nouveau/gem: off by one bugs in
    nouveau_gem_pushbuf_reloc_apply() (bsc#1051510).

  - drm/nouveau: Use drm_connector_list_iter_* for iterating
    connectors (bsc#1051510).

  - drm/radeon: fix mode_valid's return type (bsc#1051510).

  - drm: rcar-du: lvds: Fix LVDCR1 for R-Car gen3
    (bsc#1085539).

  - drm: rcar-du: Remove zpos field from
    rcar_du_vsp_plane_state structure (bsc#1085539).

  - drm: re-enable error handling (bsc#1051510).

  - drm/rockchip: analogix_dp: Remove unnecessary init code
    (bsc#1085536).

  - drm/rockchip: dw_hdmi: Move HDMI vpll clock enable to
    bind() (bsc#1087092).

  - drm/rockchip: Fix build warning in
    analogix_dp-rockchip.c (bsc#1085536).

  - drm/rockchip: inno_hdmi: Fix error handling path
    (bsc#1087092).

  - drm/rockchip: inno_hdmi: reorder clk_disable_unprepare
    call in unbind (bsc#1087092).

  - drm/tegra: Acquire a reference to the IOVA cache
    (bsc#1090888).

  - drm/udl: fix display corruption of the last line
    (bsc#1101337).

  - drm: Use kvzalloc for allocating blob property memory
    (bsc#1101352).

  - drm/vc4: Reset ->{x, y}_scaling[1] when dealing with
    uniplanar formats (bsc#1051510).

  - dvb_frontend: do not use-after-free the frontend struct
    (bsc#1051510).

  - efi/efi_test: Prevent an Oops in
    efi_runtime_query_capsulecaps() (bsc#1051510).

  - enic: do not overwrite error code (bsc#1037697).

  - enic: enable rq before updating rq descriptors
    (bsc#1037697).

  - enic: set DMA mask to 47 bit
    (networking-stable-18_06_08).

  - ethtool: add ethtool_intersect_link_masks (bsc#1101816
    ).

  - firewire: net: max MTU off by one (bsc#1051510).

  - firmware: arm_scpi: fix endianness of dev_id in struct
    dev_pstate_set (bsc#1051510).

  - firmware: dmi: Optimize dmi_matches (bsc#1051510).

  - firmware: tegra: Fix locking bugs in BPMP (bsc#1051510).

  - Fix English in description of GCC_PLUGIN_STRUCTLEAK
    (bsc#1051510).

  - Fix kABI breakage for of/device change (bsc#1051510).

  - fix kabi due to perf_event.h uapi field change ().

  - Fix kABI for rtl_deinit_deferred_work() rewrite
    (bsc#1051510).

  - fix Patch-mainline header

  - fm10k: add missing fall through comment (bsc#1101813 ).

  - fm10k: avoid divide by zero in rare cases when device is
    resetting (bsc#1101813).

  - fm10k: avoid needless delay when loading driver
    (bsc#1101813 ).

  - fm10k: avoid possible truncation of q_vector->name
    (bsc#1101813 ).

  - fm10k: bump version number (bsc#1101813).

  - fm10k: bump version number (bsc#1101813).

  - fm10k: clarify action when updating the VLAN table
    (bsc#1101813 ).

  - fm10k: cleanup unnecessary parenthesis in fm10k_iov.c
    (bsc#1101813).

  - fm10k: correct typo in fm10k_pf.c (bsc#1101813).

  - fm10k: do not assume VLAN 1 is enabled (bsc#1101813).

  - fm10k: do not loop while resetting VFs due to VFLR event
    (bsc#1101813).

  - fm10k: do not protect fm10k_queue_mac_request by
    fm10k_host_mbx_ready (bsc#1101813).

  - fm10k: Fix configuration for macvlan offload
    (bsc#1101813 ).

  - fm10k: fix 'failed to kill vid' message for VF
    (bsc#1101813 ).

  - fm10k: fix function doxygen comments (bsc#1101813).

  - fm10k: fix incorrect warning for function prototype
    (bsc#1101813 ).

  - fm10k: Fix misuse of net_ratelimit() (bsc#1101813).

  - fm10k: fix typos on fall through comments (bsc#1101813
    ).

  - fm10k: introduce a message queue for MAC/VLAN messages
    (bsc#1101813).

  - fm10k: mark PM functions as __maybe_unused (bsc#1101813
    ).

  - fm10k: move fm10k_prepare_for_reset and
    fm10k_handle_reset (bsc#1101813).

  - fm10k: prefer %s and __func__ for diagnostic prints
    (bsc#1101813 ).

  - fm10k: prepare_for_reset() when we lose PCIe Link
    (bsc#1101813 ).

  - fm10k: prevent race condition of __FM10K_SERVICE_SCHED
    (bsc#1101813).

  - fm10k: reduce duplicate fm10k_stat macro code
    (bsc#1101813 ).

  - fm10k: reschedule service event if we stall the PF<->SM
    mailbox (bsc#1101813).

  - fm10k: setup VLANs for l2 accelerated macvlan interfaces
    (bsc#1101813).

  - fm10k: simplify reading PFVFLRE register (bsc#1101813 ).

  - fm10k: stop adding VLAN 0 to the VLAN table (bsc#1101813
    ).

  - fm10k: stop spurious link down messages when Tx FIFO is
    full (bsc#1101813).

  - fm10k: use generic PM hooks instead of legacy PCIe power
    hooks (bsc#1101813).

  - fm10k: use macro to avoid passing the array and size
    separately (bsc#1101813).

  - fm10k: Use seq_putc() in fm10k_dbg_desc_break()
    (bsc#1101813 ).

  - fm10k: use spinlock to implement mailbox lock
    (bsc#1101813 ).

  - fm10k: use the MAC/VLAN queue for VF<->PF MAC/VLAN
    requests (bsc#1101813).

  - fm10k: use variadic arguments to fm10k_add_stat_strings
    (bsc#1101813).

  - fm10k: warn if the stat size is unknown (bsc#1101813 ).

  - fsi: core: register with postcore_initcall
    (bsc#1051510).

  - fuse: atomic_o_trunc should truncate pagecache
    (bsc#1051510).

  - fuse: do not keep dead fuse_conn at fuse_fill_super()
    (bsc#1051510).

  - fuse: fix congested state leak on aborted connections
    (bsc#1051510).

  - fuse: fix control dir setup and teardown (bsc#1051510).

  - fuse: Remove the buggy retranslation of pids in
    fuse_dev_do_read (bsc#1051510).

  - genirq: Check __free_irq() return value for NULL
    (bsc#1103517).

  - gpio: acpi: work around false-positive -Wstring-overflow
    warning (bsc#1051510).

  - gpio: brcmstb: allow all instances to be wakeup sources
    (bsc#1051510).

  - gpio: brcmstb: check return value of
    gpiochip_irqchip_add() (bsc#1051510).

  - gpio: brcmstb: correct the configuration of level
    interrupts (bsc#1051510).

  - gpio: brcmstb: release the bgpio lock during irq
    handlers (bsc#1051510).

  - gpio: brcmstb: switch to handle_level_irq flow
    (bsc#1051510).

  - gpio: pca953x: fix vendor prefix for PCA9654
    (bsc#1051510).

  - gpio: reject invalid gpio before getting gpio_desc
    (bsc#1051510).

  - gpio: tegra: fix unbalanced chained_irq_enter/exit
    (bsc#1051510).

  - gpu: host1x: Acquire a reference to the IOVA cache
    (bsc#1090888).

  - hid: hid-plantronics: Re-resend Update to map button for
    PTT products (bsc#1051510).

  - hid: i2c-hid: check if device is there before really
    probing (bsc#1051510).

  - hippi: Fix a Fix a possible sleep-in-atomic bug in
    rr_close (bsc#1051510).

  - hwmon: (aspeed-pwm) add THERMAL dependency
    (bsc#1051510).

  - hwmon: Deal with errors from the thermal subsystem
    (bsc#1051510).

  - hwmon: (ftsteutates) Fix clearing alarm sysfs entries
    (bsc#1051510).

  - hwmon: (ltc2990) Fix incorrect conversion of negative
    temperatures (bsc#1051510).

  - hwmon: (nct6683) Enable EC access if disabled at boot
    (bsc#1051510).

  - hwmon: (stts751) buffer overrun on wrong chip
    configuration (bsc#1051510).

  - hwmon: (tmp102) Fix first temperature reading
    (bsc#1051510).

  - hwrng: stm32 - add reset during probe (bsc#1051510).

  - i2c: axxia: enable clock before calling clk_get_rate()
    (bsc#1051510).

  - i2c: designware: Round down ACPI provided clk to nearest
    supported clk (bsc#1051510).

  - i2c: mux: pinctrl: mention correct module name in
    Kconfig help text (bsc#1051510).

  - i2c: tegra: Fix NACK error handling (bsc#1051510).

  - i40e: Add advertising 10G LR mode (bsc#1101816).

  - i40e: add check for return from find_first_bit call
    (bsc#1101816 ).

  - i40e: Add delay after EMP reset for firmware to recover
    (bsc#1101816).

  - i40e: add doxygen comment for new mode parameter
    (bsc#1101816 ).

  - i40e: add function doc headers for ethtool stats
    functions (bsc#1101816).

  - i40e: add function header for i40e_get_rxfh (bsc#1101816
    ).

  - i40e: add helper conversion function for link_speed
    (bsc#1101816 ).

  - i40e: Add infrastructure for queue channel support
    (bsc#1101816 ).

  - i40e: Add macro for PF reset bit (bsc#1101816).

  - i40e: Add new PHY types for 25G AOC and ACC support
    (bsc#1101816 ).

  - i40e: Add returning AQ critical error to SW (bsc#1101816
    ).

  - i40e: Add support for 'ethtool -m' (bsc#1101816).

  - i40e: add tx_busy to ethtool stats (bsc#1101816).

  - i40e: allow XPS with QoS enabled (bsc#1101816).

  - i40e: always return all queue stat strings (bsc#1101816
    ).

  - i40e: always return VEB stat strings (bsc#1101816).

  - i40e: avoid divide by zero (bsc#1101816).

  - i40e: avoid overflow in i40e_ptp_adjfreq() (bsc#1101816
    ).

  - i40e: broadcast filters can trigger overflow promiscuous
    (bsc#1101816).

  - i40e: calculate ethtool stats size in a separate
    function (bsc#1101816).

  - i40e: change flags to use 64 bits (bsc#1101816).

  - i40e: change ppp name to ddp (bsc#1101816).

  - i40e: check for invalid DCB config (bsc#1101816).

  - i40e: Cleanup i40e_vlan_rx_register (bsc#1101816).

  - i40e: cleanup unnecessary parens (bsc#1101816).

  - i40e: cleanup whitespace for some ethtool stat
    definitions (bsc#1101816).

  - i40e: cleanup wording in a header comment (bsc#1101816
    ).

  - i40e: convert i40e_get_settings_link_up to new API
    (bsc#1101816 ).

  - i40e: convert i40e_phy_type_to_ethtool to new API
    (bsc#1101816 ).

  - i40e: convert i40e_set_link_ksettings to new API
    (bsc#1101816 ).

  - i40e: Delete an error message for a failed memory
    allocation in i40e_init_interrupt_scheme()
    (bsc#1101816).

  - i40e: Disable iWARP VSI PETCP_ENA flag on netdev down
    events (bsc#1101816).

  - i40e: disallow programming multiple filters with same
    criteria (bsc#1101816).

  - i40e: Display error message if module does not meet
    thermal requirements (bsc#1101816).

  - i40e: display priority_xon and priority_xoff stats
    (bsc#1101816 ).

  - i40e: do not clear suspended state until we finish
    resuming (bsc#1101816).

  - i40e: do not enter PHY debug mode while setting LEDs
    behaviour (bsc#1101816).

  - i40e: do not force filter failure in overflow
    promiscuous (bsc#1101816).

  - i40e: do not hold spinlock while resetting VF
    (bsc#1101816 ).

  - i40e: do not leak memory addresses (bsc#1101816).

  - i40e: drop i40e_pf *pf from i40e_vc_disable_vf()
    (bsc#1101816 ).

  - i40e: Enable VF to negotiate number of allocated queues
    (bsc#1101816).

  - i40e: ensure reset occurs when disabling VF (bsc#1101816
    ).

  - i40e: factor out re-enable functions for ATR and SB
    (bsc#1101816 ).

  - i40e: Fix a potential NULL pointer dereference
    (bsc#1101816 ).

  - i40e: fix a typo (bsc#1101816).

  - i40e: fix a typo in i40e_pf documentation (bsc#1101816
    ).

  - i40e: fix clearing link masks in i40e_get_link_ksettings
    (bsc#1101816).

  - i40e: fix comment typo (bsc#1101816).

  - i40e: fix flags declaration (bsc#1101816).

  - i40e: Fix FLR reset timeout issue (bsc#1101816).

  - i40e: Fix for adding multiple ethtool filters on the
    same location (bsc#1101816).

  - i40e: Fix for blinking activity instead of link LEDs
    (bsc#1101816).

  - i40e: fix for flow director counters not wrapping as
    expected (bsc#1101816).

  - i40e: Fix for NUP NVM image downgrade failure
    (bsc#1101816 ).

  - i40e: fix for wrong partition id calculation on OCP mezz
    cards (bsc#1101816).

  - i40e: fix handling of vf_states variable (bsc#1101816 ).

  - i40e: fix i40e_phy_type_to_ethtool function header
    (bsc#1101816 ).

  - i40e: fix incorrect register definition (bsc#1101816).

  - i40e: Fix kdump failure (bsc#1101816).

  - i40e: Fix link down message when interface is brought up
    (bsc#1101816).

  - i40e: fix link reporting (bsc#1101816).

  - i40e: fix merge error (bsc#1101816).

  - i40e: Fix multiple issues with UDP tunnel offload filter
    configuration (bsc#1101816).

  - i40e: Fix permission check for VF MAC filters
    (bsc#1101816 ).

  - i40e: fix reading LLDP configuration (bsc#1101816).

  - i40e: Fix recalculation of MSI-X vectors for VMDq
    (bsc#1101816 ).

  - i40e: Fix reporting of supported link modes (bsc#1101816
    ).

  - i40e: Fix the polling mechanism of GLGEN_RSTAT.DEVSTATE
    (bsc#1101816).

  - i40e: fix typo in function description (bsc#1101816).

  - i40e: Fix unqualified module message while bringing link
    up (bsc#1101816).

  - i40e: fix whitespace issues in i40e_ethtool.c
    (bsc#1101816 ).

  - i40e: fold prefix strings directly into stat names
    (bsc#1101816 ).

  - i40e: free skb after clearing lock in ptp_stop
    (bsc#1101816 ).

  - i40e: free the skb after clearing the bitlock
    (bsc#1101816 ).

  - i40e: group autoneg PHY types together (bsc#1101816).

  - i40e: hold the RTNL lock while changing interrupt
    schemes (bsc#1101816).

  - i40e/i40evf: Add support for new mechanism of updating
    adaptive ITR (bsc#1101816).

  - i40e/i40evf: always set the CLEARPBA flag when
    re-enabling interrupts (bsc#1101816).

  - i40e/i40evf: Bump driver versions (bsc#1101816).

  - i40e/i40evf: bundle more descriptors when allocating
    buffers (bsc#1101816).

  - i40e/i40evf: cleanup incorrect function doxygen comments
    (bsc#1101816).

  - i40e/i40evf: Clean up logic for adaptive ITR
    (bsc#1101816 ).

  - i40e/i40evf: Clean-up of bits related to using
    q_vector->reg_idx (bsc#1101816).

  - i40e/i40evf: Detect and recover hung queue scenario
    (bsc#1101816 ).

  - i40e/i40evf: Do not bother setting the CLEARPBA bit
    (bsc#1101816 ).

  - i40e/i40evf: do not trust VF to reset itself
    (bsc#1101816 ).

  - i40e/i40evf: Enable NVMUpdate to retrieve AdminQ and add
    preservation flags for NVM update (bsc#1101816).

  - i40e/i40evf: fix incorrect default ITR values on driver
    load (bsc#1101816).

  - i40e/i40evf: Only track one ITR setting per ring instead
    of Tx/Rx (bsc#1101816).

  - i40e/i40evf: organize and re-number feature flags
    (bsc#1101816 ).

  - i40e/i40evf: Record ITR register location in the
    q_vector (bsc#1101816).

  - i40e/i40evf: rename bytes_per_int to bytes_per_usec
    (bsc#1101816 ).

  - i40e/i40evf: Split container ITR into current_itr and
    target_itr (bsc#1101816).

  - i40e/i40evf: Update DESC_NEEDED value to reflect larger
    value (bsc#1101816).

  - i40e/i40evf: use DECLARE_BITMAP for state (bsc#1101816
    ).

  - i40e/i40evf: Use ring pointers to clean up
    _set_itr_per_queue (bsc#1101816).

  - i40e/i40evf: use SW variables for hang detection
    (bsc#1101816 ).

  - i40e/i40evf: Use usec value instead of reg value for ITR
    defines (bsc#1101816).

  - i40e: ignore skb->xmit_more when deciding to set RS bit
    (bsc#1101816).

  - i40e: implement split PCI error reset handler
    (bsc#1101816 ).

  - i40e: limit lan queue count in large CPU count machine
    (bsc#1101816).

  - i40e: make const array patterns static, reduces object
    code size (bsc#1101816).

  - i40e: make i40evf_map_rings_to_vectors void (bsc#1101816
    ).

  - i40e: make use of i40e_vc_disable_vf (bsc#1101816).

  - i40e: mark PM functions as __maybe_unused (bsc#1101816
    ).

  - i40e: move AUTO_DISABLED flags into the state field
    (bsc#1101816 ).

  - i40e: move client flags into state bits (bsc#1101816).

  - i40e: move I40E_FLAG_FILTER_SYNC to a state bit
    (bsc#1101816 ).

  - i40e: move I40E_FLAG_TEMP_LINK_POLLING to state field
    (bsc#1101816).

  - i40e: move I40E_FLAG_UDP_FILTER_SYNC to the state field
    (bsc#1101816).

  - i40e: prevent service task from running while we're
    suspended (bsc#1101816).

  - i40e: Prevent setting link speed on I40E_DEV_ID_25G_B
    (bsc#1101816).

  - i40e: Prevent setting link speed on KX_X722 (bsc#1101816
    ).

  - i40e: Properly maintain flow director filters list
    (bsc#1101816 ).

  - i40e: redfine I40E_PHY_TYPE_MAX (bsc#1101816).

  - i40e: reduce lrxqthresh from 2 to 1 (bsc#1101816).

  - i40e: re-enable PTP L4 capabilities for XL710 if FW >6.0
    (bsc#1101816).

  - i40e: refactor FW version checking (bsc#1101816).

  - i40e: refactor promisc_changed in i40e_sync_vsi_filters
    (bsc#1101816).

  - i40e: relax warning message in case of version mismatch
    (bsc#1101816).

  - i40e: remove duplicate pfc stats (bsc#1101816).

  - i40e: remove i40e_fcoe files (bsc#1101816).

  - i40e: remove ifdef SPEED_25000 (bsc#1101816).

  - i40e: Remove limit of 64 max queues per channel
    (bsc#1101816 ).

  - i40e: remove logically dead code (bsc#1101816).

  - i40e: remove redundant initialization of read_size
    (bsc#1101816 ).

  - i40e: rename 'change' variable to 'autoneg_changed'
    (bsc#1101816 ).

  - i40e: rename 'cmd' variables in ethtool interface
    (bsc#1101816 ).

  - i40e: re-number feature flags to remove gaps
    (bsc#1101816 ).

  - i40e: restore promiscuous after reset (bsc#1101816).

  - i40e: restore TCPv4 input set when re-enabling ATR
    (bsc#1101816 ).

  - i40e: Retry AQC GetPhyAbilities to overcome I2CRead
    hangs (bsc#1101816).

  - i40e: shutdown all IRQs and disable MSI-X when suspended
    (bsc#1101816).

  - i40e: simplify member variable accesses (bsc#1101816).

  - i40e: split i40e_get_strings() into smaller functions
    (bsc#1101816).

  - i40e: Stop dropping 802.1ad tags - eth proto 0x88a8
    (bsc#1101816 ).

  - i40e: stop using cmpxchg flow in i40e_set_priv_flags()
    (bsc#1101816).

  - i40e: track filter type statistics when deleting invalid
    filters (bsc#1101816).

  - i40e: track id can be 0 (bsc#1101816).

  - i40e: update data pointer directly when copying to the
    buffer (bsc#1101816).

  - i40e: update VFs of link state after GET_VF_RESOURCES
    (bsc#1101816).

  - i40e: use admin queue for setting LEDs behavior
    (bsc#1101816 ).

  - i40e: use a local variable instead of calculating
    multiple times (bsc#1101816).

  - i40e: use newer generic PM support instead of legacy PM
    callbacks (bsc#1101816).

  - i40e: use separate state bit for miscellaneous IRQ setup
    (bsc#1101816).

  - i40e: use the more traditional 'i' loop variable
    (bsc#1101816 ).

  - i40e: use WARN_ONCE to replace the commented BUG_ON size
    check (bsc#1101816).

  - i40evf: Allow turning off offloads when the VF has VLAN
    set (bsc#1101816).

  - i40evf: Clean-up flags for promisc mode to avoid high
    polling rate (bsc#1101816).

  - i40evf: Correctly populate rxitr_idx and txitr_idx
    (bsc#1101816 ).

  - i40evf: Do not clear MSI-X PBA manually (bsc#1101816).

  - i40evf: Drop i40evf_fire_sw_int as it is prone to races
    (bsc#1101816).

  - i40evf: enable support for VF VLAN tag stripping control
    (bsc#1101816).

  - i40evf: Enable VF to request an alternate queue
    allocation (bsc#1101816).

  - i40evf: Fix a hardware reset support in VF driver
    (bsc#1101816 ).

  - i40evf: fix client notify of l2 params (bsc#1101816).

  - i40evf: Fix double locking the same resource
    (bsc#1101816 ).

  - i40evf: Fix link up issue when queues are disabled
    (bsc#1101816 ).

  - i40evf: fix ring to vector mapping (bsc#1101816).

  - i40evf: Fix turning TSO, GSO and GRO on after
    (bsc#1101816 ).

  - i40evf: hold the critical task bit lock while opening
    (bsc#1101816).

  - i40evf: lower message level (bsc#1101816).

  - i40evf: Make VF reset warning message more clear
    (bsc#1101816 ).

  - i40evf: release bit locks in reverse order (bsc#1101816
    ).

  - i40evf: remove flags that are never used (bsc#1101816 ).

  - i40evf: remove flush_scheduled_work call in
    i40evf_remove (bsc#1101816).

  - i40evf: Replace GFP_ATOMIC with GFP_KERNEL in
    i40evf_add_vlan (bsc#1101816).

  - i40evf: Use an iterator of the same type as the list
    (bsc#1101816).

  - i40evf: use __dev_c_sync routines in .set_rx_mode
    (bsc#1101816 ).

  - i40evf: use GFP_ATOMIC under spin lock (bsc#1101816).

  - i40evf: use spinlock to protect (mac|vlan)_filter_list
    (bsc#1101816).

  - i40e/virtchnl: fix application of sizeof to pointer
    (bsc#1101816 ).

  - i40iw: Fix memory leak in error path of create QP
    (bsc#1058659 ).

  - i40iw: Refactor of driver generated AEs (bsc#1058659 ).

  - i40iw: Tear-down connection after CQP Modify QP failure
    (bsc#1058659).

  - i40iw: Use correct address in dst_neigh_lookup for IPv6
    (bsc#1058659).

  - ib/core: Fix error code for invalid GID entry
    (bsc#1046306 ).

  - ib/core: Honor port_num while resolving GID for IB link
    layer (bsc#1046306).

  - ib/core: Make ib_mad_client_id atomic (bsc#1046306).

  - ib/core: Make testing MR flags for writability a static
    inline function (bsc#1046306).

  - ib/core: Remove duplicate declaration of gid_cache_wq
    (bsc#1046306).

  - ib/hfi1: Add bypass register defines and replace blind
    constants (bsc#1060463).

  - ib/hfi1: Fix fault injection init/exit issues
    (bsc#1060463 ).

  - ib/hfi1: Fix incorrect mixing of ERR_PTR and NULL return
    values (bsc#1060463).

  - ib/hfi1: Fix user context tail allocation for DMA_RTAIL
    (bsc#1060463).

  - ib/hfi1: Return actual error value from
    program_rcvarray() (bsc#1060463).

  - ib/iser: Do not reduce max_sectors (bsc#1046306).

  - ib/isert: Fix for lib/dma_debug check_sync warning
    (bsc#1046306 ).

  - ib/isert: fix T10-pi check mask setting (bsc#1046306 ).

  - ib/mlx4: Fix an error handling path in
    'mlx4_ib_rereg_user_mr()' (bsc#1046302).

  - ib/mlx4: Mark user MR as writable if actual virtual
    memory is writable (bsc#1046302).

  - ib/mlx5: Fetch soft WQE's on fatal error state
    (bsc#1046305 ).

  - ib/mlx5: Use 'kvfree()' for memory allocated by
    'kvzalloc()' (bsc#1046305).

  - ibmvnic: Fix error recovery on login failure
    (bsc#1101789).

  - ib/qedr: Remove GID add/del dummy routines (bsc#1086314
    bsc#1086313 bsc#1086301).

  - ib/rxe: add RXE_START_MASK for rxe_opcode
    IB_OPCODE_RC_SEND_ONLY_INV (bsc#1046306).

  - ib/rxe: avoid double kfree_skb (bsc#1046306).

  - ib/rxe: Fix for oops in rxe_register_device on ppc64le
    arch (bsc#1046306).

  - ib/umem: Use the correct mm during ib_umem_release
    (bsc#1046306 ).

  - ib/uverbs: Fix possible oops with duplicate ioctl
    attributes (bsc#1046306).

  - igb: Fix not adding filter elements to the list
    (bsc#1056651 ).

  - igb: Fix queue selection on MAC filters on i210
    (bsc#1056651 ).

  - iio: accel: st_accel: fix data-ready line configuration
    (bsc#1051510).

  - iio: accel: st_accel_i2c: fix i2c_device_id table
    (bsc#1051510).

  - iio: accel: st_accel_spi: fix spi_device_id table
    (bsc#1051510).

  - iio: adc: sun4i-gpadc-iio: fix unbalanced irq
    enable/disable (bsc#1051510).

  - iio: adc: twl4030: Return an error if we can not enable
    the vusb3v1 regulator in 'twl4030_madc_probe()'
    (bsc#1051510).

  - iio: BME280: Updates to Humidity readings need ctrl_reg
    write! (bsc#1051510).

  - iio: gyro: st_gyro: fix L3GD20H support (bsc#1051510).

  - iio: humidity: hts221: remove warnings in
    hts221_parse_{temp,rh}_caldata() (bsc#1051510).

  - iio: imu: inv_mpu6050: test whoami first and against all
    known values (bsc#1051510).

  - iio: magnetometer: st_magn_core: enable multiread by
    default for LIS3MDL (bsc#1051510).

  - iio: magnetometer: st_magn: fix drdy line configuration
    for LIS3MDL (bsc#1051510).

  - iio: magnetometer: st_magn_spi: fix spi_device_id table
    (bsc#1051510).

  - iio: pressure: bmp280: fix relative humidity unit
    (bsc#1051510).

  - iio: pressure: st_pressure: fix drdy configuration for
    LPS22HB and LPS25H (bsc#1051510).

  - iio: pressure: zpa2326: Remove always-true check which
    confuses gcc (bsc#1051510).

  - iio: pressure: zpa2326: report interrupted case as
    failure (bsc#1051510).

  - iio: trigger: stm32-timer: fix quadrature mode get
    routine (bsc#1051510).

  - iio: trigger: stm32-timer: fix write_raw return value
    (bsc#1051510).

  - iio: tsl2583: correct values in
    integration_time_available (bsc#1051510).

  - infiniband: fix a possible use-after-free bug
    (bsc#1046306 ).

  - input: elan_i2c - add ACPI ID for lenovo ideapad 330
    (bsc#1051510).

  - input: elan_i2c - add another ACPI ID for Lenovo Ideapad
    330-15AST (bsc#1051510).

  - input: i8042 - add Lenovo LaVie Z to the i8042 reset
    list (bsc#1051510).

  - iommu/vt-d: Clear Page Request Overflow fault bit ().

  - ip6_tunnel: remove magic mtu value 0xFFF8
    (networking-stable-18_06_08).

  - ipc/shm: fix use-after-free of shm file via
    remap_file_pages() (bnc#1102512).

  - ipmr: properly check rhltable_init() return value
    (networking-stable-18_06_08).

  - ipv4: remove warning in ip_recv_error
    (networking-stable-18_06_08).

  - ipv6: allow PMTU exceptions to local routes
    (networking-stable-18_06_20).

  - ipv6: sr: fix memory OOB access in
    seg6_do_srh_encap/inline (networking-stable-18_06_08).

  - iw_cxgb4: Add ib_device->get_netdev support (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - iw_cxgb4: correctly enforce the max reg_mr depth
    (bsc#1046543 ).

  - iw_cxgb4: initialize ib_mr fields for user mrs
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - iwlwifi: pcie: fix race in Rx buffer allocator
    (bsc#1051510).

  - ixgbe: add counter for times Rx pages gets allocated,
    not recycled (bsc#1101674).

  - ixgbe: add error checks when initializing the PHY
    (bsc#1101674 ).

  - ixgbe: Add receive length error counter (bsc#1101674).

  - ixgbe: add status reg reads to ixgbe_check_remove
    (bsc#1101674 ).

  - ixgbe: Add support for macvlan offload RSS on X550 and
    clean-up pool handling (bsc#1101674).

  - ixgbe: add support for reporting 5G link speed
    (bsc#1101674 ).

  - ixgbe: advertise highest capable link speed (bsc#1101674
    ).

  - ixgbe: Assume provided MAC filter has been verified by
    macvlan (bsc#1101674).

  - ixgbe: avoid bringing rings up/down as macvlans are
    added/removed (bsc#1101674).

  - ixgbe: Avoid to write the RETA table when unnecessary
    (bsc#1101674).

  - ixgbe: Clear SWFW_SYNC register during init (bsc#1101674
    ).

  - ixgbe: declare ixgbe_mac_operations structures as const
    (bsc#1101674).

  - ixgbe: Default to 1 pool always being allocated
    (bsc#1101674 ).

  - ixgbe: Do not assume dev->num_tc is equal to hardware TC
    config (bsc#1101674).

  - ixgbe: Do not manipulate macvlan Tx queues when
    performing macvlan offload (bsc#1101674).

  - ixgbe: Do not report unsupported timestamping filters
    for X550 (bsc#1101674).

  - ixgbe: Drop l2_accel_priv data pointer from ring struct
    (bsc#1101674).

  - ixgbe: Drop support for macvlan specific unicast lists
    (bsc#1101674).

  - ixgbe: enable multicast on shutdown for WOL (bsc#1101674
    ).

  - ixgbe: extend firmware version support (bsc#1101674).

  - ixgbe: Fix && vs || typo (bsc#1101674).

  - ixgbe: fix crash when injecting AER after failed reset
    (bsc#1101674).

  - ixgbe: fix disabling hide VLAN on VF reset (bsc#1101674
    ).

  - ixgbe: Fix handling of macvlan Tx offload (bsc#1101674
    ).

  - ixgbe: Fix interaction between SR-IOV and macvlan
    offload (bsc#1101674).

  - ixgbe: Fix kernel-doc format warnings (bsc#1101674).

  - ixgbe: Fix limitations on macvlan so we can support up
    to 63 offloaded devices (bsc#1101674).

  - ixgbe: fix possible race in reset subtask (bsc#1101674
    ).

  - ixgbe: fix read-modify-write in x550 phy setup
    (bsc#1101674 ).

  - ixgbe: Fix setting of TC configuration for macvlan case
    (bsc#1101674).

  - ixgbe: fix the FWSM.PT check in ixgbe_mng_present()
    (bsc#1101674 ).

  - ixgbe/fm10k: Record macvlan stats instead of Rx queue
    for macvlan offloaded rings (bsc#1101674).

  - ixgbe: force VF to grab new MAC on driver reload
    (bsc#1101674 ).

  - ixgbe: introduce a helper to simplify code (bsc#1101674
    ).

  - ixgbe/ixgbevf: Free IRQ when PCI error recovery removes
    the device (bsc#1101674).

  - ixgbe: Perform reinit any time number of VFs change
    (bsc#1101674 ).

  - ixgbe: Remove an obsolete comment about ITR (bsc#1101674
    ).

  - ixgbe: remove redundant initialization of 'pool'
    (bsc#1101674 ).

  - ixgbe: remove unused enum latency_range (bsc#1101674).

  - ixgbe: restore normal RSS after last macvlan offload is
    removed (bsc#1101674).

  - ixgbe: return error on unsupported SFP module when
    resetting (bsc#1101674).

  - ixgbe: split Tx/Rx ring clearing for ethtool loopback
    test (bsc#1101674).

  - ixgbe: There is no need to update num_rx_pools in L2 fwd
    offload (bsc#1101674).

  - ixgbe: Update adaptive ITR algorithm (bsc#1101674).

  - ixgbe: use ARRAY_SIZE for array sizing calculation on
    array buf (bsc#1101674).

  - ixgbe: Use ring values to test for Tx pending
    (bsc#1101674 ).

  - ixgbevf: add build_skb support (bsc#1101674).

  - ixgbevf: add counters for Rx page allocations
    (bsc#1101674 ).

  - ixgbevf: add ethtool private flag for legacy Rx
    (bsc#1101674 ).

  - ixgbevf: add function for checking if we can reuse page
    (bsc#1101674).

  - ixgbevf: add support for
    DMA_ATTR_SKIP_CPU_SYNC/WEAK_ORDERING (bsc#1101674).

  - ixgbevf: add support for padding packet (bsc#1101674).

  - ixgbevf: add support for using order 1 pages to receive
    large frames (bsc#1101674).

  - ixgbevf: allocate the rings as part of q_vector
    (bsc#1101674 ).

  - ixgbevf: break out Rx buffer page management
    (bsc#1101674 ).

  - ixgbevf: clear rx_buffer_info in configure instead of
    clean (bsc#1101674).

  - ixgbevf: do not bother clearing tx_buffer_info in
    ixgbevf_clean_tx_ring() (bsc#1101674).

  - ixgbevf: fix ixgbevf_xmit_frame()'s return type
    (bsc#1101674 ).

  - ixgbevf: Fix kernel-doc format warnings (bsc#1101674).

  - ixgbevf: fix MAC address changes through
    ixgbevf_set_mac() (bsc#1101674).

  - ixgbevf: fix possible race in the reset subtask
    (bsc#1101674 ).

  - ixgbevf: fix unused variable warning (bsc#1101674).

  - ixgbevf: improve performance and reduce size of
    ixgbevf_tx_map() (bsc#1101674).

  - ixgbevf: make sure all frames fit minimum size
    requirements (bsc#1101674).

  - ixgbevf: only DMA sync frame length (bsc#1101674).

  - ixgbevf: remove redundant initialization of variable
    'dma' (bsc#1101674).

  - ixgbevf: remove redundant setting of xcast_mode
    (bsc#1101674 ).

  - ixgbevf: setup queue counts (bsc#1101674).

  - ixgbevf: update code to better handle incrementing page
    count (bsc#1101674).

  - ixgbevf: use ARRAY_SIZE for various array sizing
    calculations (bsc#1101674).

  - ixgbevf: use length to determine if descriptor is done
    (bsc#1101674).

  - ixgbevf: use page_address offset from page (bsc#1101674
    ).

  - jump_label: Add branch hints to
    static_branch_{un,}likely() (bnc#1101669 optimise numa
    balancing for fast migrate).

  - kabi cxgb4 MU (bsc#1097585 bsc#1097586 bsc#1097587
    bsc#1097588 bsc#1097583 bsc#1097584).

  - kcm: Fix use-after-free caused by clonned sockets
    (networking-stable-18_06_08).

  - kernel/params.c: downgrade warning for unsafe parameters
    (bsc#1051510).

  - keys: DNS: fix parsing multiple options (bsc#1051510).

  - kvm: PPC: Check if IOMMU page is contained in the pinned
    physical page (bsc#1077761, git-fixes).

  - kvm: x86: fix vcpu initialization with userspace lapic
    (bsc#1101564).

  - kvm: x86: move LAPIC initialization after VMCS creation
    (bsc#1101564).

  - libnvdimm: add an api to cast a 'struct nd_region' to
    its 'struct device' (bsc#1094119).

  - libnvdimm, label: fix index block size calculation
    (bsc#1102147).

  - mailbox: bcm2835: Fix of_xlate return value
    (bsc#1051510).

  - mailbox: PCC: erroneous error message when parsing ACPI
    PCCT (bsc#1096330).

  - mdio-sun4i: Fix a memory leak (bsc#1051510).

  - media: coda/imx-vdoa: Check for platform_get_resource()
    error (bsc#1051510).

  - media: cx25840: Use subdev host data for PLL override
    (bsc#1051510).

  - media: cx88: Get rid of spurious call to
    cx8800_start_vbi_dma() (bsc#1051510).

  - media: cxusb: restore RC_MAP for MyGica T230
    (bsc#1051510).

  - media: dt-bindings: media: rcar_vin: Use status 'okay'
    (bsc#1051510).

  - media: dvb-core: always call invoke_release() in
    fe_free() (bsc#1051510).

  - media: dvb_frontend: fix ifnullfree.cocci warnings
    (bsc#1051510).

  - media: dvb_frontend: only use kref after initialized
    (bsc#1051510).

  - media: dvb_net: ensure that dvb_net_ule_handle is fully
    initialized (bsc#1051510).

  - media: media-device: fix ioctl function types
    (bsc#1051510).

  - media: mxl111sf: Fix potential NULL pointer dereference
    (bsc#1051510).

  - media: omap3isp/isp: remove an unused static var
    (bsc#1051510).

  - media: rcar_jpu: Add missing clk_disable_unprepare() on
    error in jpu_open() (bsc#1051510).

  - media: s5p-jpeg: fix number of components macro
    (bsc#1051510).

  - media: s5p-mfc: Fix lock contention - request_firmware()
    once (bsc#1051510).

  - media: saa7164: Fix driver name in debug output
    (bsc#1051510).

  - media: si470x: fix __be16 annotations (bsc#1051510).

  - media: siano: get rid of __le32/__le16 cast warnings
    (bsc#1051510).

  - media: staging: omap4iss: Include asm/cacheflush.h after
    generic includes (bsc#1051510).

  - media: tw686x: Fix incorrect vb2_mem_ops GFP flags
    (bsc#1051510).

  - media: vivid: potential integer overflow in
    vidioc_g_edid() (bsc#1051510).

  - mfd: tps65218: Reorder tps65218_regulator_id enum
    (bsc#1051510).

  - mfd: tps65911-comparator: Fix a build error
    (bsc#1051510).

  - mfd: tps65911-comparator: Fix an off by one bug
    (bsc#1051510).

  - mlxsw: spectrum: Forbid creation of VLAN 1 over port/LAG
    (networking-stable-18_06_08).

  - mmc: cavium: Fix use-after-free in
    of_platform_device_destroy (bsc#1051510).

  - mmc: dw_mmc: fix card threshold control configuration
    (bsc#1051510).

  - mmc: dw_mmc: update actual clock for mmc debugfs
    (bsc#1051510).

  - mmc: meson-gx: remove CLK_DIVIDER_ALLOW_ZERO clock flag
    (bsc#1051510).

  - mmc: pwrseq: Use kmalloc_array instead of stack VLA
    (bsc#1051510).

  - mmc: sdhci-msm: fix issue with power irq (bsc#1051510).

  - mmc: sdhci-of-esdhc: disable SD clock for clock value 0
    (bsc#1051510).

  - mmc: sdhci-of-esdhc: fix eMMC couldn't work after kexec
    (bsc#1051510).

  - mmc: sdhci-of-esdhc: fix the mmc error after sleep on
    ls1046ardb (bsc#1051510).

  - mmc: sdhci-xenon: Fix clock resource by adding an
    optional bus clock (bsc#1051510).

  - mmc: sdhci-xenon: wait 5ms after set 1.8V signal enable
    (bsc#1051510).

  - mmc: tmio: remove outdated comment (bsc#1051510).

  - modsign: log module name in the event of an error
    (bsc#1093666).

  - modsign: print module name along with error message
    (bsc#1093666).

  - module: make it clear when we're handling the module
    copy in info->hdr (bsc#1093666).

  - module: setup load info before module_sig_check()
    (bsc#1093666).

  - mvpp2: fix multicast address filter (bsc#1098633).

  - mwifiex: correct histogram data with appropriate index
    (bsc#1051510).

  - mwifiex: handle race during mwifiex_usb_disconnect
    (bsc#1051510).

  - net: add rb_to_skb() and other rb tree helpers
    (bsc#1102340).

  - net: cxgb3_main: fix potential Spectre v1 (bsc#1046533
    ).

  - net: define the TSO header size in net/tso.h
    (bsc#1098633).

  - netdev-FAQ: clarify DaveM's position for stable
    backports (networking-stable-18_06_08).

  - net: dsa: add error handling for pskb_trim_rcsum
    (networking-stable-18_06_20).

  - net: ethernet: davinci_emac: fix error handling in
    probe() (networking-stable-18_06_08).

  - net: ethernet: ti: cpdma: correct error handling for
    chan create (networking-stable-18_06_08).

  - net: ethtool: Add macro to clear a link mode setting
    (bsc#1101816).

  - net: in virtio_net_hdr only add VLAN_HLEN to csum_start
    if payload holds vlan (networking-stable-18_06_20).

  - net: ipv4: add missing RTA_TABLE to rtm_ipv4_policy
    (networking-stable-18_06_08).

  - net: metrics: add proper netlink validation
    (networking-stable-18_06_08).

  - net/mlx4_core: Fix error handling in mlx4_init_port_info
    (bsc#1046300).

  - net/mlx4_core: Save the qpn from the input modifier in
    RST2INIT wrapper (bsc#1046300).

  - net/mlx4_en: Do not reuse RX page when XDP is set
    (bsc#1046299 ).

  - net/mlx4: Fix irq-unsafe spinlock usage
    (networking-stable-18_06_08).

  - net/mlx5: Adjust clock overflow work period
    (bsc#1046303).

  - net/mlx5e: Do not allow aRFS for encapsulated packets
    (bsc#1046303).

  - net/mlx5e: Do not attempt to dereference the ppriv
    struct if not being eswitch manager (bsc#1046300).

  - net/mlx5e: Fix quota counting in aRFS expire flow
    (bsc#1046303 ).

  - net/mlx5e: Refine ets validation function (bsc#1075360).

  - net/mlx5e: Remove redundant vport context vlan update
    (bsc#1046303).

  - net/mlx5: Eswitch, Use 'kvfree()' for memory allocated
    by 'kvzalloc()' (bsc#1046303).

  - net/mlx5e: When RXFCS is set, add FCS data into checksum
    calculation (networking-stable-18_06_08).

  - net/mlx5: Fix command interface race in polling mode
    (bsc#1046300).

  - net/mlx5: Fix dump_command mailbox length printed
    (bsc#1046303 ).

  - net/mlx5: Fix incorrect raw command length parsing
    (bsc#1046300 ).

  - net/mlx5: Fix wrong size allocation for QoS ETC TC
    regitster (bsc#1046300).

  - net/mlx5: FPGA, Call DMA unmap with the right size
    (bsc#1046303 ).

  - net/mlx5: Free IRQs in shutdown path (bsc#1046303).

  - net/mlx5: IPSec, Fix a race between concurrent sandbox
    QP commands (bsc#1046303).

  - net/mlx5: Properly deal with flow counters when deleting
    rules (bsc#1046303).

  - net/mlx5: Protect from command bit overflow (bsc#1046303
    ).

  - net/mlx5: Refactor num of blocks in mailbox calculation
    (bsc#1046303).

  - net/mlx5: Vport, Use 'kvfree()' for memory allocated by
    'kvzalloc()' (bsc#1046303).

  - net: mvmdio: add xmdio xsmi support (bsc#1098633).

  - net: mvmdio: check the MII_ADDR_C45 bit is not set for
    smi operations (bsc#1098633).

  - net: mvmdio: introduce an ops structure (bsc#1098633).

  - net: mvmdio: put the poll intervals in the ops structure
    (bsc#1098633).

  - net: mvmdio: remove duplicate locking (bsc#1098633).
    Refresh
    patches.suse/net-mvmdio-disable-unprepare-clocks-in-EPRO
    BE_DEFER-.patch.

  - net: mvmdio: reorder headers alphabetically
    (bsc#1098633).

  - net: mvmdio: simplify the smi read and write error paths
    (bsc#1098633).

  - net: mvmdio: use GENMASK for masks (bsc#1098633).

  - net: mvmdio: use tabs for defines (bsc#1098633).

  - net: mvpp2: add comments about smp_processor_id() usage
    (bsc#1098633).

  - net: mvpp2: add ethtool GOP statistics (bsc#1098633).

  - net: mvpp2: Add hardware offloading for VLAN filtering
    (bsc#1098633).

  - net: mvpp2: add support for TX interrupts and RX queue
    distribution modes (bsc#1098633).

  - net: mvpp2: Add support for unicast filtering
    (bsc#1098633).

  - net: mvpp2: adjust the coalescing parameters
    (bsc#1098633).

  - net: mvpp2: align values in ethtool get_coalesce
    (bsc#1098633).

  - net: mvpp2: allocate zeroed tx descriptors
    (bsc#1098633).

  - net: mvpp2: check ethtool sets the Tx ring size is to a
    valid min value (bsc#1098633).

  - net: mvpp2: cleanup probed ports in the probe error path
    (bsc#1098633).

  - net: mvpp2: do not call txq_done from the Tx path when
    Tx irqs are used (bsc#1098633).

  - net: mvpp2: do not disable GMAC padding (bsc#1098633).

  - net: mvpp2: do not select the internal source clock
    (bsc#1098633).

  - net: mvpp2: do not set GMAC autoneg when using XLG MAC
    (bsc#1098633).

  - net: mvpp2: do not sleep in set_rx_mode (bsc#1098633).

  - net: mvpp2: do not unmap TSO headers buffers
    (bsc#1098633).

  - net: mvpp2: Do not use dynamic allocs for local
    variables (bsc#1098633).

  - net: mvpp2: dynamic reconfiguration of the
    comphy/GoP/MAC (bsc#1098633).

  - net: mvpp2: enable ACPI support in the driver
    (bsc#1098633).

  - net: mvpp2: enable basic 10G support (bsc#1098633).

  - net: mvpp2: enable UDP/TCP checksum over IPv6
    (bsc#1098633).

  - net: mvpp2: fallback using h/w and random mac if the dt
    one isn't valid (bsc#1098633).

  - net: mvpp2: Fix clk error path in mvpp2_probe
    (bsc#1098633).

  - net: mvpp2: Fix clock resource by adding an optional bus
    clock (bsc#1098633).

  - net: mvpp2: Fix clock resource by adding missing
    mg_core_clk (bsc#1098633).

  - net: mvpp2: Fix DMA address mask size (bsc#1098633).

  - net: mvpp2: fix GOP statistics loop start and stop
    conditions (bsc#1098633).

  - net: mvpp2: fix invalid parameters order when calling
    the tcam init (bsc#1098633).

  - net: mvpp2: fix MVPP21_ISR_RXQ_GROUP_REG definition
    (bsc#1098633).

  - net: mvpp2: Fix parser entry init boundary check
    (bsc#1098633).

  - net: mvpp2: fix parsing fragmentation detection
    (bsc#1098633).

  - net: mvpp2: fix port list indexing (bsc#1098633).

  - net: mvpp2: Fix TCAM filter reserved range
    (bsc#1098633).

  - net: mvpp2: fix the packet size configuration for 10G
    (bsc#1098633).

  - net: mvpp2: fix the RSS table entry offset
    (bsc#1098633).

  - net: mvpp2: fix the synchronization module bypass macro
    name (bsc#1098633).

  - net: mvpp2: fix the txq_init error path (bsc#1098633).

  - net: mvpp2: fix TSO headers allocation and management
    (bsc#1098633).

  - net: mvpp2: fix typo in the tcam setup (bsc#1098633).

  - net: mvpp2: fix use of the random mac address for PPv2.2
    (bsc#1098633).

  - net: mvpp2: improve the link management function
    (bsc#1098633).

  - net: mvpp2: initialize the comphy (bsc#1098633).

  - net: mvpp2: initialize the GMAC when using a port
    (bsc#1098633).

  - net: mvpp2: initialize the GoP (bsc#1098633).

  - net: mvpp2: initialize the RSS tables (bsc#1098633).

  - net: mvpp2: initialize the Tx FIFO size (bsc#1098633).

  - net: mvpp2: initialize the XLG MAC when using a port
    (bsc#1098633).

  - net: mvpp2: introduce per-port nrxqs/ntxqs variables
    (bsc#1098633).

  - net: mvpp2: introduce queue_vector concept
    (bsc#1098633).

  - net: mvpp2: jumbo frames support (bsc#1098633).

  - net: mvpp2: limit TSO segments and use stop/wake
    thresholds (bsc#1098633).

  - net: mvpp2: Make mvpp2_prs_hw_read a parser entry init
    function (bsc#1098633).

  - net: mvpp2: make the phy optional (bsc#1098633).

  - net: mvpp2: move from cpu-centric naming to 'software
    thread' naming (bsc#1098633).

  - net: mvpp2: move the mac retrieval/copy logic into its
    own function (bsc#1098633).

  - net: mvpp2: move the mii configuration in the ndo_open
    path (bsc#1098633).

  - net: mvpp2: mvpp2_check_hw_buf_num() can be static
    (bsc#1098633).

  - net: mvpp2: only free the TSO header buffers when it was
    allocated (bsc#1098633).

  - net: mvpp2: Prevent userspace from changing TX
    affinities (bsc#1098633).

  - net: mvpp2: remove mvpp2_pool_refill() (bsc#1098633).

  - net: mvpp2: remove RX queue group reset code
    (bsc#1098633).

  - net: mvpp2: remove unused mvpp2_bm_cookie_pool_set()
    function (bsc#1098633).

  - net: mvpp2: remove useless goto (bsc#1098633).

  - net: mvpp2: report the tx-usec coalescing information to
    ethtool (bsc#1098633).

  - net: mvpp2: set maximum packet size for 10G ports
    (bsc#1098633).

  - net: mvpp2: set the Rx FIFO size depending on the port
    speeds for PPv2.2 (bsc#1098633).

  - net: mvpp2: Simplify MAC filtering function parameters
    (bsc#1098633).

  - net: mvpp2: simplify maintaining enabled ports' list
    (bsc#1098633).

  - net: mvpp2: simplify the link_event function
    (bsc#1098633).

  - net: mvpp2: simplify the Tx desc set DMA logic
    (bsc#1098633).

  - net: mvpp2: software tso support (bsc#1098633).

  - net: mvpp2: split the max ring size from the default one
    (bsc#1098633).

  - net: mvpp2: take advantage of the is_rgmii helper
    (bsc#1098633).

  - net: mvpp2: unify register definitions coding style
    (bsc#1098633).

  - net: mvpp2: unify the txq size define use (bsc#1098633).

  - net: mvpp2: update the BM buffer free/destroy logic
    (bsc#1098633).

  - net: mvpp2: use a data size of 10kB for Tx FIFO on port
    0 (bsc#1098633).

  - net: mvpp2: use correct index on array mvpp2_pools
    (bsc#1098633).

  - net: mvpp2: use device_*/fwnode_* APIs instead of of_*
    (bsc#1098633).

  - net: mvpp2: Use relaxed I/O in data path (bsc#1098633).

  - net: mvpp2: use the aggr txq size define everywhere
    (bsc#1098633).

  - net: mvpp2: use the GoP interrupt for link status
    changes (bsc#1098633).

  - net: mvpp2: use the same buffer pool for all ports
    (bsc#1098633).

  - net/packet: refine check for priv area size
    (networking-stable-18_06_08).

  - net: phy: add XAUI and 10GBASE-KR PHY connection types
    (bsc#1098633).

  - net: phy: broadcom: Fix auxiliary control register reads
    (networking-stable-18_06_08).

  - net: phy: broadcom: Fix bcm_write_exp()
    (networking-stable-18_06_08).

  - net: phy: dp83822: use BMCR_ANENABLE instead of
    BMSR_ANEGCAPABLE for DP83620
    (networking-stable-18_06_20).

  - net: qed: use correct strncpy() size (bsc#1086314
    bsc#1086313 bsc#1086301).

  - net/sched: act_simple: fix parsing of TCA_DEF_DATA
    (networking-stable-18_06_20).

  - net/sched: act_tunnel_key: fix NULL dereference when
    'goto chain' is used (bsc#1056787).

  - net/sched: fix NULL dereference in the error path of
    tcf_sample_init() (bsc#1056787).

  - net: sched: red: avoid hashing NULL child (bsc#1056787).

  - net-sysfs: Fix memory leak in XPS configuration
    (networking-stable-18_06_08).

  - net: usb: cdc_mbim: add flag FLAG_SEND_ZLP
    (networking-stable-18_06_08).

  - nfc: nfcmrvl_uart: fix device-node leak during probe
    (bsc#1051510).

  - nfc: pn533: Fix wrong GFP flag usage (bsc#1051510).

  - nfit, address-range-scrub: add module option to skip
    initial ars (bsc#1094119).

  - nfit, address-range-scrub: determine one platform
    max_ars value (bsc#1094119).

  - nfit, address-range-scrub: fix scrub in-progress
    reporting (bsc#1051510).

  - nfit, address-range-scrub: introduce nfit_spa->ars_state
    (bsc#1094119).

  - nfit, address-range-scrub: rework and simplify ARS state
    machine (bsc#1094119).

  - nfit: fix region registration vs block-data-window
    ranges (bsc#1051510).

  - nfit: fix unchecked dereference in acpi_nfit_ctl
    (bsc#1051510).

  - nvme: add ANA support (bsc#1054245).

  - nvme: add bio remapping tracepoint (bsc#1054245).

  - nvme: centralize ctrl removal prints (bsc#1054245).

  - nvme: cleanup double shift issue (bsc#1054245).

  - nvme: do not enable AEN if not supported (bsc#1077989).

  - nvme: do not hold nvmf_transports_rwsem for more than
    transport lookups (bsc#1054245).

  - nvme: do not rely on the changed namespace list log
    (bsc#1054245).

  - nvme: enforce 64bit offset for nvme_get_log_ext fn
    (bsc#1054245).

  - nvme: fix handling of metadata_len for NVME_IOCTL_IO_CMD
    ().

  - nvme: Fix sync controller reset return (bsc#1077989).

  - nvme: fix use-after-free in nvme_free_ns_head
    (bsc#1054245).

  - nvme: guard additional fields in nvme command structures
    (bsc#1054245).

  - nvme.h: add AEN configuration symbols (bsc#1054245).

  - nvme.h: add ANA definitions (bsc#1054245).

  - nvme.h: add support for the log specific field
    (bsc#1054245).

  - nvme.h: add the changed namespace list log
    (bsc#1054245).

  - nvme: host: core: fix precedence of ternary operator
    (bsc#1054245).

  - nvme.h: untangle AEN notice definitions (bsc#1054245).

  - nvme: if_ready checks to fail io to deleting controller
    (bsc#1077989).

  - nvme: implement log page low/high offset and dwords
    (bsc#1054245).

  - nvme: kabi fixes for nvme_ctrl (bsc#1054245).

  - nvme: kABI fixes for nvmet_ctrl (bsc#1054245).

  - nvme: kABI fix for ANA support in nvme_ctrl
    (bsc#1054245).

  - nvme-loop: add support for multiple ports (bsc#1054245).

  - nvme: make nvme_get_log_ext non-static (bsc#1054245).

  - nvme: mark nvme_queue_scan static (bsc#1054245).

  - nvme/multipath: Disable runtime writable enabling
    parameter (bsc#1054245).

  - nvme: partially revert 'nvme: remove
    nvme_req_needs_failover' (bsc#1054245).

  - nvme: reintruduce nvme_get_log_ext() (bsc#1054245).

  - nvme: remove nvme_req_needs_failover (bsc#1054245).

  - nvme: simplify the API for getting log pages
    (bsc#1054245).

  - nvme: submit AEN event configuration on startup
    (bsc#1054245).

  - nvmet: add AEN configuration support (bsc#1054245).

  - nvmet: add a new nvmet_zero_sgl helper (bsc#1054245).

  - nvmet: add minimal ANA support (bsc#1054245).

  - nvmet: constify struct nvmet_fabrics_ops (bsc#1054245).

  - nvmet-fc: fix target sgl list on large transfers ().

  - nvmet: filter newlines from user input (bsc#1054245).

  - nvmet: fixup crash on NULL device path (bsc#1054245).

  - nvmet: implement the changed namespaces log
    (bsc#1054245).

  - nvmet: kABI fixes for ANA support (bsc#1054245).

  - nvmet: keep a port pointer in nvmet_ctrl (bsc#1054245).

  - nvmet: mask pending AENs (bsc#1054245).

  - nvmet: reset keep alive timer in controller enable
    (bsc#1054245).

  - nvmet: return all zeroed buffer when we can't find an
    active namespace (bsc#1054245).

  - nvmet: split log page implementation (bsc#1054245).

  - nvmet: support configuring ANA groups (bsc#1054245).

  - nvmet: track and limit the number of namespaces per
    subsystem (1054245).

  - nvmet: use Retain Async Event bit to clear AEN
    (bsc#1054245).

  - nvme: use the changed namespaces list log to clear ns
    data changed AENs (bsc#1054245).

  - of: fix DMA mask generation (bsc#1051510).

  - of: Make of_fwnode_handle() safer (bsc#1098633).

  - of/pci: Fix theoretical NULL dereference (bsc#1051510).

  - of: restrict DMA configuration (bsc#1051510).

  - pci: Account for all bridges on bus when distributing
    bus numbers (bsc#1100132).

  - pci: altera: Fix bool initialization in
    tlp_read_packet() (bsc#1051510).

  - pci: dwc: Fix enumeration end when reaching root
    subordinate (bsc#1100132).

  - pci: endpoint: Fix kernel panic after put_device()
    (bsc#1051510).

  - pci: endpoint: Populate func_no before calling
    pci_epc_add_epf() (bsc#1051510).

  - pci: exynos: Fix a potential init_clk_resources NULL
    pointer dereference (bsc#1051510).

  - pci: faraday: Fix of_irq_get() error check
    (bsc#1051510).

  - pci: ibmphp: Fix use-before-set in get_max_bus_speed()
    (bsc#1051510).

  - pci: pciehp: Assume NoCompl+ for Thunderbolt ports
    (bsc#1051510).

  - pci: pciehp: Request control of native hotplug only if
    supported (bsc#1051510).

  - pci: Prevent sysfs disable of device while driver is
    attached (bsc#1051510).

  - pci: shpchp: Fix AMD POGO identification (bsc#1051510).

  - perf intel-pt: Always set no branch for dummy event
    (bsc#1087217).

  - perf intel-pt: Set no_aux_samples for the tracking event
    (bsc#1087217).

  - perf/x86: Fix data source decoding for Skylake ().

  - perf/x86/intel/uncore: Add event constraint for BDX PCU
    (bsc#1087202).

  - perf/x86/intel/uncore: Fix missing marker for
    skx_uncore_cha_extra_regs (bsc#1087233).

  - perf/x86/intel/uncore: Fix SKX CHA event extra regs
    (bsc#1087233).

  - perf/x86/intel/uncore: Fix Skylake server CHA LLC_LOOKUP
    event umask (bsc#1087233).

  - perf/x86/intel/uncore: Fix Skylake server PCU PMU event
    format (bsc#1087233).

  - perf/x86/intel/uncore: Fix Skylake UPI PMU event masks
    (bsc#1087233).

  - perf/x86/intel/uncore: Remove invalid Skylake server CHA
    filter field (bsc#1087233).

  - phy: add sgmii and 10gkr modes to the phy_mode enum
    (bsc#1098633).

  - pinctrl: at91-pio4: add missing of_node_put
    (bsc#1051510).

  - pinctrl: bcm2835: Avoid warning from
    __irq_do_set_handler (bsc#1051510).

  - pinctrl: imx: fix debug message for SHARE_MUX_CONF_REG
    case (bsc#1051510).

  - pinctrl: intel: Initialize GPIO properly when used
    through irqchip (bsc#1087092).

  - pinctrl: intel: Read back TX buffer state (bsc#1051510).

  - pinctrl: meson-gxbb: remove non-existing pin GPIOX_22
    (bsc#1051510).

  - pinctrl: meson-gxl: Fix typo in AO I2S pins
    (bsc#1051510).

  - pinctrl: meson-gxl: Fix typo in AO SPDIF pins
    (bsc#1051510).

  - pinctrl: mvebu: use correct MPP sel value for dev pins
    (bsc#1051510).

  - pinctrl: nand: meson-gxbb: fix missing data pins
    (bsc#1051510).

  - pinctrl: nsp: Fix potential NULL dereference
    (bsc#1051510).

  - pinctrl: nsp: off by ones in nsp_pinmux_enable()
    (bsc#1100132).

  - pinctrl: pinctrl-single: Fix pcs_request_gpio() when
    bits_per_mux != 0 (bsc#1051510).

  - pinctrl: sh-pfc: r8a7790: Add missing TX_ER pin to
    avb_mii group (bsc#1051510).

  - pinctrl: sh-pfc: r8a7795: Fix MOD_SEL register pin
    assignment for SSI pins group (bsc#1051510).

  - pinctrl: sh-pfc: r8a7795: Fix to delete A20..A25 pins
    function definitions (bsc#1051510).

  - pinctrl: sh-pfc: r8a7796: Fix IPSR and MOD_SEL register
    pin assignment for NDFC pins group (bsc#1051510).

  - pinctrl: sh-pfc: r8a7796: Fix to delete A20..A25 pins
    function definitions (bsc#1051510).

  - pinctrl: sh-pfc: r8a7796: Fix to delete FSCLKST pin and
    IPSR7 bit[15:12] register definitions (bsc#1051510).

  - pinctrl: sunxi: fix V3s pinctrl driver IRQ bank base
    (bsc#1051510).

  - pinctrl: sunxi: fix wrong irq_banks number for H5
    pinctrl (bsc#1051510).

  - pinctrl: uniphier: fix members of rmii group for Pro4
    (bsc#1051510).

  - pinctrl: uniphier: fix pin_config_get() for input-enable
    (bsc#1051510).

  - pm / core: Fix supplier device runtime PM usage counter
    imbalance (bsc#1051510).

  - pm / hibernate: Fix oops at snapshot_write()
    (bsc#1051510).

  - pm / hibernate: Use CONFIG_HAVE_SET_MEMORY for include
    condition (bsc#1051510).

  - pm / wakeup: Only update last time for active wakeup
    sources (bsc#1051510).

  - power: gemini-poweroff: Avoid spurious poweroff
    (bsc#1051510).

  - powerpc/64: Fix smp_wmb barrier definition use use
    lwsync consistently (bnc#1012382).

  - powerpc/64s: Clear PCR on boot (bnc#1012382).

  - powerpc/64s: Fix section mismatch warnings from
    setup_rfi_flush() (bsc#1068032, bsc#1075087,
    bsc#1091041).

  - powerpc: Add missing prototype for arch_irq_work_raise()
    (bnc#1012382).

  - powerpc/eeh: Fix enabling bridge MMIO windows
    (bnc#1012382).

  - powerpc/fadump: Unregister fadump on kexec down path
    (bnc#1012382).

  - powerpc/mm/hash: Add missing isync prior to kernel stack
    SLB switch (bnc#1012382).

  - powerpc/mpic: Check if cpu_possible() in mpic_physmask()
    (bnc#1012382).

  - powerpc/powernv: define a standard delay for OPAL_BUSY
    type retry loops (bnc#1012382).

  - powerpc/powernv: Fix NVRAM sleep in invalid context when
    crashing (bnc#1012382).

  - powerpc/powernv: Fix OPAL NVRAM driver OPAL_BUSY loops
    (bnc#1012382).

  - powerpc/powernv: Handle unknown OPAL errors in
    opal_nvram_write() (bnc#1012382).

  - powerpc/ptrace: Fix setting 512B aligned breakpoints
    with PTRACE_SET_DEBUGREG (bnc#1012382).

  - power: supply: act8945a_charger: fix of_irq_get() error
    check (bsc#1051510).

  - power: supply: cpcap-charger: add OMAP_USB2 dependency
    (bsc#1051510).

  - pwm: meson: Fix allocation of PWM channel array
    (bsc#1051510).

  - pwm: meson: Improve PWM calculation precision
    (bsc#1051510).

  - pwm: stm32: Enforce dependency on
    CONFIG_MFD_STM32_TIMERS (bsc#1051510).

  - pwm: stm32: Remove unused struct device (bsc#1051510).

  - pwm: tiehrpwm: fix clock imbalance in probe error path
    (bsc#1051510).

  - pwm: tiehrpwm: Fix runtime PM imbalance at unbind
    (bsc#1051510).

  - qed: Adapter flash update support (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed: Add APIs for flash access (bsc#1086314 bsc#1086313
    bsc#1086301).

  - qed: Add configuration information to register dump and
    debug data (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Add driver infrastucture for handling mfw requests
    (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - qed: Add MFW interfaces for TLV request support
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed* : Add new TLV to request PF to update MAC in
    bulletin board (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - qed: Add sanity check for SIMD fastpath handler
    (bsc#1050536 ).

  - qed: Add support for multi function mode with 802.1ad
    tagging (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - qed: Add support for processing fcoe tlv request
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Add support for processing iscsi tlv request
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Add support for tlv request processing (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed: Add support for Unified Fabric Port (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed*: Advance drivers' version to 8.33.0.20 (bsc#1086314
    ).

  - qed: code indent should use tabs where possible
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Correct Multicast API to reflect existence of 256
    approximate buckets (bsc#1050536).

  - qed: Delete unused parameter p_ptt from mcp APIs
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Do not advertise DCBX_LLD_MANAGED capability
    (bsc#1050536 ).

  - qede: Add build_skb() support (bsc#1086314 bsc#1086313
    bsc#1086301).

  - qede: Add support for populating ethernet TLVs
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qede: Adverstise software timestamp caps when PHC is not
    available (bsc#1050538).

  - qede: Do not drop rx-checksum invalidated packets
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qede: Ethtool flash update support (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qede: Fix barrier usage after tx doorbell write
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qede: Fix ref-cnt usage count (bsc#1086314 bsc#1086313
    bsc#1086301).

  - qede: fix spelling mistake: 'registeration' ->
    'registration' (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - qede: Refactor ethtool rx classification flow
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qede: Support flow classification to the VFs
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qede: Use NETIF_F_GRO_HW (bsc#1086314 bsc#1086313
    bsc#1086301).

  - qede: Validate unsupported configurations (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed: Fix copying 2 strings (bsc#1086314 bsc#1086313
    bsc#1086301).

  - qed: Fix link flap issue due to mismatching EEE
    capabilities (bsc#1050536).

  - qed: Fix LL2 race during connection terminate
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Fix mask for physical address in ILT entry
    (networking-stable-18_06_08).

  - qed: Fix possibility of list corruption during rmmod
    flows (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - qed: Fix possible memory leak in Rx error path handling
    (bsc#1050536).

  - qed: Fix possible race for the link state value
    (bsc#1050536 ).

  - qed: Fix potential use-after-free in qed_spq_post()
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Fix PTT entry leak in the selftest error flow
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Fix reading stale configuration information
    (bsc#1086314 ).

  - qed: Fix setting of incorrect eswitch mode (bsc#1050536
    ).

  - qed: Fix shared memory inconsistency between driver and
    the MFW (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - qed: fix spelling mistake: 'checksumed' -> 'checksummed'
    (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - qed: fix spelling mistake: 'offloded' -> 'offloaded'
    (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - qed: fix spelling mistake: 'taskelt' -> 'tasklet'
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Fix use of incorrect shmem address (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed: Fix use of incorrect size in memcpy call
    (bsc#1050536 ).

  - qed: Free reserved MR tid (bsc#1086314 bsc#1086313
    bsc#1086301).

  - qed*: HSI renaming for different types of HW
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Limit msix vectors in kdump kernel to the minimum
    required count (bsc#1050536).

  - qed: LL2 flush isles when connection is closed
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: off by one in qed_parse_mcp_trace_buf()
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Populate nvm image attribute shadow (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed*: Refactoring and rearranging FW API with no
    functional impact (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed*: Refactor mf_mode to consist of bits (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed: Remove reserveration of dpi for kernel (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed: Remove unused data member 'is_mf_default'
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qedr: Fix spelling mistake: 'hanlde' -> 'handle'
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed*: Support drop action classification (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed*: Support other classification modes (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed: use kzalloc instead of kmalloc and memset
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - qed: Use true and false for boolean values (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qed* : use trust mode to allow VF to override forced MAC
    (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - qed: Use zeroing memory allocator than allocator/memset
    (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - qed*: Utilize FW 8.33.1.0 (bsc#1086314 bsc#1086313
    bsc#1086301).

  - qed*: Utilize FW 8.33.11.0 (bsc#1086314 bsc#1086313
    bsc#1086301).

  - qlogic: check kstrtoul() for errors (bsc#1050540).

  - qlogic/qed: Constify *pkt_type_str (bsc#1086314
    bsc#1086313 bsc#1086301).

  - qmi_wwan: add support for Quectel EG91 (bsc#1051510).

  - qmi_wwan: add support for the Dell Wireless 5821e module
    (bsc#1051510).

  - qmi_wwan: fix interface number for DW5821e production
    firmware (bsc#1051510).

  - qmi_wwan: set FLAG_SEND_ZLP to avoid network initiated
    disconnect (bsc#1051510).

  - r8152: fix tx packets accounting (bsc#1051510).

  - r8152: napi hangup fix after disconnect (bsc#1051510).

  - r8169: Be drop monitor friendly (bsc#1051510).

  - rbd: flush rbd_dev->watch_dwork after watch is
    unregistered (bsc#1103216).

  - rdma/cma: Do not query GID during QP state transition to
    RTR (bsc#1046306).

  - rdma/cma: Fix use after destroy access to net namespace
    for IPoIB (bsc#1046306).

  - rdma/cxgb4: release hw resources on device removal
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - rdma/cxgb4: Use structs to describe the uABI instead of
    opencoding (bsc#1097585 bsc#1097586 bsc#1097587
    bsc#1097588 bsc#1097583 bsc#1097584).

  - rdma/i40iw: Avoid panic when objects are being created
    and destroyed (bsc#1058659).

  - rdma/i40iw: Avoid reference leaks when processing the
    AEQ (bsc#1058659).

  - rdma/ipoib: Update paths on CLIENT_REREG/SM_CHANGE
    events (bsc#1046307).

  - rdma/iwpm: fix memory leak on map_info (bsc#1046306 ).

  - rdma/mlx4: Discard unknown SQP work requests
    (bsc#1046302 ).

  - rdma/mlx5: Do not assume that medium blueFlame register
    exists (bsc#1046305).

  - rdma/mlx5: Fix memory leak in mlx5_ib_create_srq() error
    path (bsc#1046305).

  - rdma/mlx5: Fix multiple NULL-ptr deref errors in
    rereg_mr flow (bsc#1046305).

  - rdma/mlx5: Fix NULL dereference while accessing XRC_TGT
    QPs (bsc#1046305).

  - rdma/mlx5: Protect from shift operand overflow
    (bsc#1046305 ).

  - rdma/mlx5: Use proper spec flow label type (bsc#1046305
    ).

  - rdma/qedr: Annotate iomem pointers correctly
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - rdma/qedr: Declare local functions static (bsc#1086314
    bsc#1086313 bsc#1086301).

  - rdma/qedr: eliminate duplicate barriers on
    weakly-ordered archs (bsc#1086314 bsc#1086313
    bsc#1086301 ).

  - rdma/qedr: Fix doorbell bar mapping for dpi > 1
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - rdma/qedr: Fix endian problems around imm_data
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - rdma/qedr: Fix ipv6 destination address resolution
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - rdma/qedr: Fix iWARP connect with port mapper
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - rdma/qedr: Fix iWARP write and send with immediate
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - rdma/qedr: Fix kernel panic when running fio over
    NFSoRDMA (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - rdma/qedr: Fix wmb usage in qedr (bsc#1086314
    bsc#1086313 bsc#1086301).

  - rdma/qedr: lower print level of flushed CQEs
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - rdma/qedr: Remove set-but-not-used variables
    (bsc#1086314 bsc#1086313 bsc#1086301).

  - rdma/qedr: Use NULL instead of 0 to represent a pointer
    (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - rdma/qedr: Use zeroing memory allocator than
    allocator/memset (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - rdma/qedr: Zero stack memory before copying to user
    space (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - rdma/ucma: Do not allow setting RDMA_OPTION_IB_PATH
    without an RDMA device (bsc#1046306).

  - rdma/ucma: ucma_context reference leak in error path
    (bsc#1046306).

  - rdma/uverbs: Protect from attempts to create flows on
    unsupported QP (bsc#1046306).

  - rdma/uverbs: Use an unambiguous errno for method not
    supported (bsc#1046306).

  - regulator: max8998: Fix platform data retrieval
    (bsc#1051510).

  - regulator: pfuze100: add .is_enable() for
    pfuze100_swb_regulator_ops (bsc#1051510).

  - regulator: qcom_spmi: Include offset when translating
    voltages (bsc#1051510).

  - regulator: tps65218: Fix strobe assignment
    (bsc#1051510).

  - Revert 'drm/nouveau/drm/therm/fan: add a fallback if no
    fan control is specified in the vbios' (bsc#1103356).

  - Revert 'nvme: mark nvme_queue_scan static'
    (bsc#1054245).

  - Revert 'nvmet: constify struct nvmet_fabrics_ops'
    (bsc#1054245).

  - Revert 'xhci: plat: Register shutdown for xhci_plat'
    (bsc#1090888).

  - rpm/kernel-source.spec.in: Add more stuff to Recommends
    ... and move bc to Recommends as well. All these
    packages are needed for building a kernel manually from
    scratch with kernel-source files.

  - rpm/kernel-source.spec.in: require bc for kernel-source
    This is needed for building
    include/generated/timeconst.h from
    kernel/time/timeconst.bc.

  - rtc: ac100: Fix ac100 determine rate bug (bsc#1051510).

  - rtc: pxa: fix probe function (bsc#1051510).

  - rtlwifi: Fix kernel Oops 'Fw download fail!!'
    (bsc#1051510).

  - rtlwifi: rtl8821ae: fix firmware is not ready to run
    (bsc#1051510).

  - rtnetlink: validate attributes in do_setlink()
    (networking-stable-18_06_08).

  - s390: add assembler macros for CPU alternatives
    (git-fixes f19fbd5ed6).

  - s390/cio: clear timer when terminating driver I/O
    (bsc#1103421).

  - s390/cio: fix return code after missing interrupt
    (bsc#1103421).

  - s390: correct module section names for expoline code
    revert (git-fixes f19fbd5ed6).

  - s390: Correct register corruption in critical section
    cleanup (git-fixes 6dd85fbb87).

  - s390/crc32-vx: use expoline for indirect branches
    (git-fixes f19fbd5ed6).

  - s390/dasd: fix handling of internal requests
    (bsc#1103421).

  - s390/dasd: fix wrongly assigned configuration data
    (bsc#1103421).

  - s390/dasd: prevent prefix I/O error (bsc#1103421).

  - s390/eadm: fix CONFIG_BLOCK include dependency
    (bsc#1103421).

  - s390: extend expoline to BC instructions (git-fixes,
    bsc#1103421).

  - s390/ftrace: use expoline for indirect branches
    (git-fixes f19fbd5ed6).

  - s390/gs: add compat regset for the guarded storage
    broadcast control block (git-fixes e525f8a6e696).

  - s390/ipl: ensure loadparm valid flag is set
    (bsc#1103421).

  - s390/kernel: use expoline for indirect branches
    (git-fixes f19fbd5ed6).

  - s390/lib: use expoline for indirect branches (git-fixes
    f19fbd5ed6).

  - s390: move expoline assembler macros to a header
    (git-fixes f19fbd5ed6).

  - s390: move spectre sysfs attribute code (bsc#1090098).

  - s390: optimize memset implementation (git-fixes
    f19fbd5ed6).

  - s390/pci: do not require AIS facility (bsc#1103421).

  - s390/qdio: do not release memory in qdio_setup_irq()
    (bsc#1103421).

  - s390/qdio: do not retry EQBS after CCQ 96 (bsc#1102088,
    LTC#169699).

  - s390/qeth: fix error handling in adapter command
    callbacks (bsc#1102088, LTC#169699).

  - s390/qeth: fix race when setting MAC address
    (bnc#1093148, LTC#167307).

  - s390: remove indirect branch from do_softirq_own_stack
    (git-fixes f19fbd5ed6).

  - s390: use expoline thunks in the BPF JIT (git-fixes,
    bsc#1103421).

  - sched/core: Optimize ttwu_stat() (bnc#1101669 optimise
    numa balancing for fast migrate).

  - sched/core: Optimize update_stats_*() (bnc#1101669
    optimise numa balancing for fast migrate).

  - scripts/dtc: fix '%zx' warning (bsc#1051510).

  - scripts/gdb/linux/tasks.py: fix get_thread_info
    (bsc#1051510).

  - scripts/git_sort/git_sort.py: add modules-next tree

  - scripts/git_sort/git_sort.py: Add 'nvme-4.18' to the
    list of repositories

  - scripts/kernel-doc: Do not fail with status != 0 if
    error encountered with -none (bsc#1051510).

  - scsi: aacraid: Correct hba_send to include iu_type
    (bsc#1077989).

  - scsi: core: clean up generated file scsi_devinfo_tbl.c
    (bsc#1077989).

  - scsi: cxgb4i: silence overflow warning in
    t4_uld_rx_handler() (bsc#1097585 bsc#1097586 bsc#1097587
    bsc#1097588 bsc#1097583 bsc#1097584).

  - scsi: megaraid_sas: Do not log an error if FW
    successfully initializes (bsc#1077989).

  - scsi: qla2xxx: Fix inconsistent DMA mem alloc/free
    (bsc#1077989).

  - scsi: qla2xxx: Fix kernel crash due to late workqueue
    allocation (bsc#1077338).

  - scsi: zfcp: fix infinite iteration on ERP ready list
    (bsc#1102088, LTC#169699).

  - scsi: zfcp: fix misleading REC trigger trace where
    erp_action setup failed (bsc#1102088, LTC#169699).

  - scsi: zfcp: fix missing REC trigger trace for all
    objects in ERP_FAILED (bsc#1102088, LTC#169699).

  - scsi: zfcp: fix missing REC trigger trace on enqueue
    without ERP thread (bsc#1102088, LTC#169699).

  - scsi: zfcp: fix missing REC trigger trace on
    terminate_rport_io early return (bsc#1102088,
    LTC#169699).

  - scsi: zfcp: fix missing REC trigger trace on
    terminate_rport_io for ERP_FAILED (bsc#1102088,
    LTC#169699).

  - scsi: zfcp: fix missing SCSI trace for result of
    eh_host_reset_handler (bsc#1102088, LTC#169699).

  - scsi: zfcp: fix missing SCSI trace for retry of abort /
    scsi_eh TMF (bsc#1102088, LTC#169699).

  - sctp: not allow transport timeout value less than HZ/5
    for hb_timer (networking-stable-18_06_08).

  - serial: earlycon: Only try fdt when specify 'earlycon'
    exactly (bsc#1051510).

  - serial: imx: drop if that always evaluates to true
    (bsc#1051510).

  - serial: pxa: Fix out-of-bounds access through serial
    port index (bsc#1051510).

  - serial: sh-sci: Update warning message in
    sci_request_dma_chan() (bsc#1051510).

  - serial: sh-sci: Use spin_{try}lock_irqsave instead of
    open coding version (bsc#1051510).

  - serial: sirf: Fix out-of-bounds access through DT alias
    (bsc#1051510).

  - sfc: stop the TX queue before pushing new buffers
    (bsc#1058169 ).

  - smsc75xx: Add workaround for gigabit link up hardware
    errata (bsc#1051510).

  - smsc75xx: fix smsc75xx_set_features() (bsc#1051510).

  - smsc95xx: Configure pause time to 0xffff when tx flow
    control enabled (bsc#1051510).

  - soc: bcm2835: Make !RASPBERRYPI_FIRMWARE dummies return
    failure (bsc#1051510).

  - soc: bcm: raspberrypi-power: Fix use of __packed
    (bsc#1051510).

  - soc: imx: gpc: de-register power domains only if
    initialized (bsc#1051510).

  - soc: imx: gpc: restrict register range for regmap access
    (bsc#1051510).

  - soc: imx: gpcv2: correct PGC offset (bsc#1051510).

  - soc: imx: gpcv2: Do not pass static memory as platform
    data (bsc#1051510).

  - soc: imx: gpcv2: fix regulator deferred probe
    (bsc#1051510).

  - socket: close race condition between sock_close() and
    sockfs_setattr() (networking-stable-18_06_20).

  - soc: mediatek: pwrap: fix compiler errors (bsc#1051510).

  - soc: qcom: wcnss_ctrl: Fix increment in NV upload
    (bsc#1051510).

  - soc: rockchip: power-domain: Fix wrong value when power
    up pd with writemask (bsc#1051510).

  - soc/tegra: Fix bad of_node_put() in powergate init
    (bsc#1051510).

  - soc/tegra: flowctrl: Fix error handling (bsc#1051510).

  - soc: ti: ti_sci_pm_domains: Populate name for genpd
    (bsc#1051510).

  - soc: zte: Restrict SOC_ZTE to ARCH_ZX or COMPILE_TEST
    (bsc#1051510).

  - spi: bcm2835aux: ensure interrupts are enabled for
    shared handler (bsc#1051510).

  - spi/bcm63xx-hspi: Enable the clock before calling
    clk_get_rate() (bsc#1051510).

  - spi: bcm-qspi: Always read and set BSPI_MAST_N_BOOT_CTRL
    (bsc#1051510).

  - spi: bcm-qspi: Avoid setting MSPI_CDRAM_PCS for spi-nor
    master (bsc#1051510).

  - spi: bcm-qspi: fIX some error handling paths
    (bsc#1051510).

  - spi: cadence: Add usleep_range() for
    cdns_spi_fill_tx_fifo() (bsc#1051510).

  - spi: core: Fix devm_spi_register_master() function name
    in kerneldoc (bsc#1051510).

  - spi: pxa2xx: Allow 64-bit DMA (bsc#1051510).

  - spi: pxa2xx: check clk_prepare_enable() return value
    (bsc#1051510).

  - spi: pxa2xx: Do not touch CS pin until we have a
    transfer pending (bsc#1051510).

  - spi: sh-msiof: Fix bit field overflow writes to
    TSCR/RSCR (bsc#1051510).

  - staging: comedi: quatech_daqp_cs: fix no-op loop
    daqp_ao_insn_write() (bsc#1051510).

  - staging: fbtft: array underflow in
    fbtft_request_gpios_match() (bsc#1051510).

  - staging: iio: ade7759: fix signed extension bug on shift
    of a u8 (bsc#1051510).

  - staging:iio:ade7854: Fix error handling on read/write
    (bsc#1051510).

  - staging:iio:ade7854: Fix the wrong number of bits to
    read (bsc#1051510).

  - staging: rtl8723bs: add missing range check on id
    (bsc#1051510).

  - staging: rtl8723bs: fix u8 less than zero check
    (bsc#1051510).

  - staging: rtl8723bs: Prevent an underflow in
    rtw_check_beacon_data() (bsc#1051510).

  - staging: rts5208: Fix 'seg_no' calculation in
    reset_ms_card() (bsc#1051510).

  - staging: sm750fb: Fix parameter mistake in poke32
    (bsc#1051510).

  - tcp: verify the checksum of the first data segment in a
    new connection (networking-stable-18_06_20).

  - team: use netdev_features_t instead of u32
    (networking-stable-18_06_08).

  - thermal: bcm2835: fix an error code in probe()
    (bsc#1051510).

  - thermal/drivers/hisi: Fix kernel panic on alarm
    interrupt (bsc#1051510).

  - thermal/drivers/hisi: Fix missing interrupt enablement
    (bsc#1051510).

  - thermal/drivers/hisi: Fix multiple alarm interrupts
    firing (bsc#1051510).

  - thermal/drivers/hisi: Simplify the temperature/step
    computation (bsc#1051510).

  - thermal: exynos: fix setting rising_threshold for
    Exynos5433 (bsc#1051510).

  - thermal: fix INTEL_SOC_DTS_IOSF_CORE dependencies
    (bsc#1051510).

  - timekeeping: Use proper timekeeper for debug code
    (bsc#1051510).

  - time: Make sure jiffies_to_msecs() preserves non-zero
    time periods (bsc#1051510).

  - tools/libbpf: handle issues with bpf ELF objects
    containing .eh_frames (bsc#1051510).

  - tools/lib/lockdep: Define the ARRAY_SIZE() macro
    (bsc#1051510).

  - tools/lib/lockdep: Fix undefined symbol prandom_u32
    (bsc#1051510).

  - tools lib traceevent: Fix get_field_str() for dynamic
    strings (bsc#1051510).

  - tools lib traceevent: Simplify pointer print logic and
    fix %pF (bsc#1051510).

  - tools/power turbostat: Correct SNB_C1/C3_AUTO_UNDEMOTE
    defines (bsc#1051510).

  - tools/thermal: tmon: fix for segfault (bsc#1051510).

  - tools/usbip: fixes build with musl libc toolchain
    (bsc#1051510).

  - tty: Fix data race in tty_insert_flip_string_fixed_flag
    (bsc#1051510).

  - ubi: fastmap: Correctly handle interrupted erasures in
    EBA (bsc#1051510).

  - ubifs: Fix data node size for truncating uncompressed
    nodes (bsc#1051510).

  - ubifs: Fix potential integer overflow in allocation
    (bsc#1051510).

  - ubifs: Fix uninitialized variable in search_dh_cookie()
    (bsc#1051510).

  - ubifs: Fix unlink code wrt. double hash lookups
    (bsc#1051510).

  - udp: fix rx queue len reported by diag and proc
    interface (networking-stable-18_06_20).

  - Update config files: enable CONFIG_I2C_PXA for arm64
    (bsc#1101465)

  - usb: audio-v2: Correct the comment for struct
    uac_clock_selector_descriptor (bsc#1051510).

  - usb: cdc_acm: Add quirk for Castles VEGA3000
    (bsc#1051510).

  - usb: cdc_acm: Add quirk for Uniden UBC125 scanner
    (bsc#1051510).

  - usb: cdc_acm: prevent race at write to acm while system
    resumes (bsc#1087092).

  - usb: core: handle hub C_PORT_OVER_CURRENT condition
    (bsc#1051510).

  - usb: do not reset if a low-speed or full-speed device
    timed out (bsc#1051510).

  - usb: dwc2: debugfs: Do not touch RX FIFO during register
    dump (bsc#1051510).

  - usb: dwc2: Fix DMA alignment to start at allocated
    boundary (bsc#1051510).

  - usb: dwc2: Fix dwc2_hsotg_core_init_disconnected()
    (bsc#1051510).

  - usb: dwc2: fix the incorrect bitmaps for the ports of
    multi_tt hub (bsc#1051510).

  - usb: dwc2: hcd: Fix host channel halt flow
    (bsc#1051510).

  - usb: dwc2: host: Fix transaction errors in host mode
    (bsc#1051510).

  - usb: dwc2: Improve gadget state disconnection handling
    (bsc#1085539).

  - usb: dwc3: Add SoftReset PHY synchonization delay
    (bsc#1051510).

  - usb: dwc3: ep0: Reset TRB counter for ep0 IN
    (bsc#1051510).

  - usb: dwc3: Fix GDBGFIFOSPACE_TYPE values (bsc#1051510).

  - usb: dwc3: gadget: Fix list_del corruption in
    dwc3_ep_dequeue (bsc#1051510).

  - usb: dwc3: gadget: Set maxpacket size for ep0 IN
    (bsc#1051510).

  - usb: dwc3: Makefile: fix link error on randconfig
    (bsc#1051510).

  - usb: dwc3: of-simple: fix use-after-free on remove
    (bsc#1051510).

  - usb: dwc3: omap: do not miss events during
    suspend/resume (bsc#1051510).

  - usb: dwc3: pci: Properly cleanup resource (bsc#1051510).

  - usb: dwc3: prevent setting PRTCAP to OTG from debugfs
    (bsc#1051510).

  - usb: dwc3: Undo PHY init if soft reset fails
    (bsc#1051510).

  - usb: dwc3: Update DWC_usb31 GTXFIFOSIZ reg fields
    (bsc#1051510).

  - usb: gadget: bdc: 64-bit pointer capability check
    (bsc#1051510).

  - usb: gadget: composite: fix incorrect handling of OS
    desc requests (bsc#1051510).

  - usb: gadget: core: Fix use-after-free of usb_request
    (bsc#1051510).

  - usb: gadget: dummy: fix nonsensical comparisons
    (bsc#1051510).

  - usb: gadget: ffs: Execute copy_to_user() with USER_DS
    set (bsc#1051510).

  - usb: gadget: f_fs: Fix use-after-free in
    ffs_fs_kill_sb() (bsc#1051510).

  - usb: gadget: ffs: Let setup() return
    USB_GADGET_DELAYED_STATUS (bsc#1051510).

  - usb: gadget: f_fs: Only return delayed status when len
    is 0 (bsc#1051510).

  - usb: gadget: f_fs: Process all descriptors during bind
    (bsc#1051510).

  - usb: gadget: f_fs: Use config_ep_by_speed()
    (bsc#1051510).

  - usb/gadget: Fix 'high bandwidth' check in
    usb_gadget_ep_match_desc() (bsc#1051510).

  - usb: gadget: f_mass_storage: Fix the logic to iterate
    all common->luns (bsc#1051510).

  - usb: gadget: f_midi: fixing a possible double-free in
    f_midi (bsc#1051510).

  - usb: gadget: fsl_udc_core: fix ep valid checks
    (bsc#1051510).

  - usb: gadget: f_uac2: fix bFirstInterface in composite
    gadget (bsc#1051510).

  - usb: gadget: f_uac2: fix endianness of 'struct
    cntrl_*_lay3' (bsc#1051510).

  - usb: gadget: f_uac2: fix error handling in afunc_bind
    (again) (bsc#1051510).

  - usb: gadget: udc: Add missing platform_device_put() on
    error in bdc_pci_probe() (bsc#1051510).

  - usb: gadget: udc: change comparison to bitshift when
    dealing with a mask (bsc#1051510).

  - usb: gadget: udc: core: update usb_ep_queue()
    documentation (bsc#1051510).

  - usb: gadget: udc: renesas_usb3: disable the controller's
    irqs for reconnecting (bsc#1051510).

  - usb: host: ehci: use correct device pointer for dma ops
    (bsc#1087092).

  - usb: host: xhci-plat: revert 'usb: host: xhci-plat:
    enable clk in resume timing' (bsc#1051510).

  - usb: hub: Do not wait for connect state at resume for
    powered-off ports (bsc#1051510).

  - usb: Increment wakeup count on remote wakeup
    (bsc#1051510).

  - usbip: Correct maximum value of
    CONFIG_USBIP_VHCI_HC_PORTS (bsc#1051510).

  - usbip: usbip_detach: Fix memory, udev context and udev
    leak (bsc#1051510).

  - usbip: usbip_event: fix to not print kernel pointer
    address (bsc#1051510).

  - usbip: usbip_host: refine probe and disconnect debug
    msgs to be useful (bsc#1051510).

  - usbip: vhci_hcd: Fix usb device and sockfd leaks
    (bsc#1051510).

  - usbip: vhci_sysfs: fix potential Spectre v1
    (bsc#1051510).

  - usb: ldusb: add PIDs for new CASSY devices supported by
    this driver (bsc#1051510).

  - usb: musb: call pm_runtime_{get,put}_sync before reading
    vbus registers (bsc#1051510).

  - usb: musb: fix enumeration after resume (bsc#1051510).

  - usb: musb: Fix external abort in musb_remove on omap2430
    (bsc#1051510).

  - usb: musb: fix remote wakeup racing with suspend
    (bsc#1051510).

  - usb: musb: gadget: misplaced out of bounds check
    (bsc#1051510).

  - usb: musb: host: fix potential NULL pointer dereference
    (bsc#1051510).

  - usb: musb: trace: fix NULL pointer dereference in
    musb_g_tx() (bsc#1051510).

  - usb: OHCI: Fix NULL dereference in HCDs using
    HCD_LOCAL_MEM (bsc#1087092).

  - usb: option: Add support for FS040U modem (bsc#1087092).

  - usb: quirks: add delay quirks for Corsair Strafe
    (bsc#1051510).

  - usb: serial: ch341: fix type promotion bug in
    ch341_control_in() (bsc#1051510).

  - usb: serial: cp210x: add another USB ID for Qivicon
    ZigBee stick (bsc#1051510).

  - usb: serial: cp210x: add CESINEL device ids
    (bsc#1051510).

  - usb: serial: cp210x: add ELDAT Easywave RX09 id
    (bsc#1051510).

  - usb: serial: cp210x: add ID for NI USB serial console
    (bsc#1051510).

  - usb: serial: cp210x: add Silicon Labs IDs for Windows
    Update (bsc#1051510).

  - usb: serial: ftdi_sio: add RT Systems VX-8 cable
    (bsc#1051510).

  - usb: serial: ftdi_sio: add support for Harman
    FirmwareHubEmulator (bsc#1051510).

  - usb: serial: ftdi_sio: use jtag quirk for Arrow USB
    Blaster (bsc#1051510).

  - usb: serial: keyspan_pda: fix modem-status error
    handling (bsc#1100132).

  - usb: serial: mos7840: fix status-register error handling
    (bsc#1051510).

  - usb: serial: option: adding support for ublox R410M
    (bsc#1051510).

  - usb: serial: option: Add support for Quectel EP06
    (bsc#1051510).

  - usb: serial: option: reimplement interface masking
    (bsc#1051510).

  - usb: serial: simple: add libtransistor console
    (bsc#1051510).

  - usb: serial: visor: handle potential invalid device
    configuration (bsc#1051510).

  - usb-storage: Add compatibility quirk flags for
    G-Technologies G-Drive (bsc#1051510).

  - usb-storage: Add support for FL_ALWAYS_SYNC flag in the
    UAS driver (bsc#1051510).

  - usb: yurex: fix out-of-bounds uaccess in read handler
    (bsc#1100132).

  - vfio/pci: Fix potential Spectre v1 (bsc#1051510).

  - vfio/spapr: Use IOMMU pageshift rather than pagesize
    (bsc#1077761, git-fixes).

  - vhost: synchronize IOTLB message with dev cleanup
    (networking-stable-18_06_08).

  - video/omap: add module license tags (bsc#1090888).

  - video: remove unused kconfig SH_LCD_MIPI_DSI
    (bsc#1087092).

  - virtio_balloon: fix another race between migration and
    ballooning (bsc#1051510).

  - virtio-net: correctly transmit XDP buff after
    linearizing (networking-stable-18_06_08).

  - virtio_net: Disable interrupts if napi_complete_done
    rescheduled napi (bsc#1051510).

  - virtio-net: fix leaking page for gso packet during
    mergeable XDP (networking-stable-18_06_08).

  - virtio-net: fix module unloading (bsc#1051510).

  - virtio-net: Fix operstate for virtio when no
    VIRTIO_NET_F_STATUS (bsc#1051510).

  - virtio_net: fix XDP code path in receive_small()
    (bsc#1051510).

  - vmcore: add API to collect hardware dump in second
    kernel (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - vrf: check the original netdevice for generating
    redirect (networking-stable-18_06_08).

  - wlcore: add missing nvs file name info for wilink8
    (bsc#1051510).

  - wlcore: sdio: check for valid platform device data
    before suspend (bsc#1051510).

  - x.509: unpack RSA signatureValue field from BIT STRING
    (bsc#1051510).

  - x86/efi: Access EFI MMIO data as unencrypted when SEV is
    active (bsc#1099193).

  - xen/grant-table: log the lack of grants (bnc#1085042).

  - xhci: Fix kernel oops in trace_xhci_free_virt_device
    (bsc#1100132).

  - xhci: Fix USB3 NULL pointer dereference at logical
    disconnect (bsc#1090888).

  - xhci: Fix use-after-free in xhci_free_virt_device
    (bsc#1100132).

  - xhci: xhci-mem: off by one in xhci_stream_id_to_ring()
    (bsc#1100132)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085042"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103730"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.10.1") ) flag++;

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
