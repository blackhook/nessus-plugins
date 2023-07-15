#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0041.
#

include("compat.inc");

if (description)
{
  script_id(109668);
  script_version("1.9");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2017-0861", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-15115", "CVE-2017-15868", "CVE-2017-16525", "CVE-2017-16526", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16531", "CVE-2017-16533", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16649", "CVE-2017-5715", "CVE-2017-7482", "CVE-2017-8824", "CVE-2017-9074", "CVE-2018-100199", "CVE-2018-8897");

  script_name(english:"OracleVM 3.3 : Unbreakable / etc (OVMSA-2018-0041) (Spectre)");
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

  - x86/entry/64: Don't use IST entry for #BP stack (Andy
    Lutomirski) (CVE-2018-8897)

  - perf/hwbp: Simplify the perf-hwbp code, fix
    documentation (Linus Torvalds) [Orabug: 27947608]
    (CVE-2018-100199)

  - x86/microcode: probe CPU features on microcode update
    (Ankur Arora) 

  - x86/microcode: microcode_write should not reference
    boot_cpu_data (Ankur Arora) [Orabug: 27806667]

  - x86/cpufeatures: use cpu_data in
    init_scattered_cpuid_flags (Ankur Arora) [Orabug:
    27806667]

  - Drivers: hv: fcopy: set .owner reference for file
    operations (Joe Jin) [Orabug: 21191022]

  - ALSA: usb-audio: Kill stray URB at exiting (Takashi
    Iwai) [Orabug: 27148281] (CVE-2017-16527)

  - HID: usbhid: fix out-of-bounds bug (Jaejoong Kim)
    [Orabug: 27207929] (CVE-2017-16533)

  - [media] cx231xx-cards: fix NULL-deref on missing
    association descriptor (Johan Hovold) [Orabug: 27208072]
    (CVE-2017-16536)

  - net: cdc_ether: fix divide by 0 on bad descriptors
    (Bj&oslash rn Mork) [Orabug: 27215201] (CVE-2017-16649)

  - x86/microcode/intel: Extend BDW late-loading with a
    revision check (Jia Zhang) [Orabug: 27343577]

  - x86/microcode/intel: Disable late loading on model 79
    (Borislav Petkov) [Orabug: 27343577]

  - Bluetooth: bnep: bnep_add_connection should verify that
    it's dealing with l2cap socket (Al Viro) [Orabug:
    27344793] (CVE-2017-15868)

  - Bluetooth: hidp: verify l2cap sockets (David Herrmann)
    [Orabug: 27344793] (CVE-2017-15868)

  - ALSA: pcm: prevent UAF in snd_pcm_info (Robb Glasser)
    [Orabug: 27344843] (CVE-2017-0861) (CVE-2017-0861)

  - ptrace: use fsuid, fsgid, effective creds for fs access
    checks (Jann Horn) [Orabug: 27364691] (CVE-2017-14140)

  - sctp: do not peel off an assoc from one netns to another
    one (Xin Long) [Orabug: 27387001] (CVE-2017-15115)

  - Revert 'x86/spec_ctrl: Add 'nolfence' knob to disable
    fallback for spectre_v2 mitigation' (Ankur Arora)
    [Orabug: 27601787] (CVE-2017-5715)

  - Revert 'x86/spec: Add 'lfence_enabled' in sysfs' (Ankur
    Arora) [Orabug: 27601787] (CVE-2017-5715)

  - Revert 'x86/mitigation/spectre_v2: Add reporting of
    'lfence'' (Ankur Arora) [Orabug: 27601787]
    (CVE-2017-5715)

  - x86/mitigation/spectre_v2: Add reporting of 'lfence'
    (Konrad Rzeszutek Wilk) (CVE-2017-5715)

  - x86/spec: Add 'lfence_enabled' in sysfs (Konrad
    Rzeszutek Wilk) (CVE-2017-5715)

  - x86/spec_ctrl: Add 'nolfence' knob to disable fallback
    for spectre_v2 mitigation (Konrad Rzeszutek Wilk)
    (CVE-2017-5715)

  - x86/spectre: bring spec_ctrl management logic closer to
    UEK4 (Ankur Arora) [Orabug: 27516512] (CVE-2017-5715)

  - x86/cpufeatures: Clean up Spectre v2 related CPUID flags
    (David Woodhouse) [Orabug: 27516357] (CVE-2017-5715)

  - x86/spectre_v2: Remove 0xc2 from spectre_bad_microcodes
    (Darren Kenny) [Orabug: 27516419] (CVE-2017-5715)

  - x86/cpufeature: Blacklist SPEC_CTRL/PRED_CMD on early
    Spectre v2 microcodes (David Woodhouse) [Orabug:
    27516419] (CVE-2017-5715)

  - x86: intel-family.h: Add GEMINI_LAKE SOC (Len Brown)
    [Orabug: 27516419]

  - x86/cpu/intel: Introduce macros for Intel family numbers
    (Dave Hansen) [Orabug: 27516419]

  - x86/spectre: expose 'stibp' (Konrad Rzeszutek Wilk)
    [Orabug: 27516419] (CVE-2017-5715)

  - x86/speculation: Add basic IBPB (Indirect Branch
    Prediction Barrier) support (David Woodhouse) [Orabug:
    27516379] (CVE-2017-5715)

  - x86/speculation: Use Indirect Branch Prediction Barrier
    in context switch (Tim Chen) [Orabug: 27516379]
    (CVE-2017-5715)

  - x86/spectre: fix spectre_v1 mitigation indicators (Ankur
    Arora) [Orabug: 27509932] (CVE-2017-5715)

  - x86/ia32/syscall: Clear extended registers %r8-%r15
    (Ankur Arora) [Orabug: 27452028] (CVE-2017-5715)

  - x86/ia32/syscall: Save full stack frame throughout the
    entry code (Ankur Arora) [Orabug: 27452028]
    (CVE-2017-5715)

  - x86/ia32/syscall: cleanup trailing whitespace (Ankur
    Arora) [Orabug: 27452028] (CVE-2017-5715)

  - x86/syscall: Clear callee saved registers (%r12-%r15,
    %rbp, %rbx) (Ankur Arora) [Orabug: 27452028]
    (CVE-2017-5715)

  - x86/syscall: Save callee saved registers on syscall
    entrance (Ankur Arora) [Orabug: 27452028]
    (CVE-2017-5715)

  - gre: fix a possible skb leak (Eric Dumazet) [Orabug:
    26403972] (CVE-2017-9074)

  - ipv6: Fix leak in ipv6_gso_segment. (David S. Miller)
    [Orabug: 26403972] (CVE-2017-9074)

  - ipv6: xfrm: Handle errors reported by
    xfrm6_find_1stfragopt (Ben Hutchings) [Orabug: 26403972]
    (CVE-2017-9074)

  - ipv6: Check ip6_find_1stfragopt return value properly.
    (David S. Miller) [Orabug: 26403972] (CVE-2017-9074)

  - ipv6: Prevent overrun when parsing v6 header options
    (Craig Gallek) [Orabug: 26403972] (CVE-2017-9074)

  - tcp: initialize rcv_mss to TCP_MIN_MSS instead of 0 (Wei
    Wang) [Orabug: 26813390] (CVE-2017-14106)

  - rxrpc: Fix several cases where a padded len isn't
    checked in ticket decode (David Howells) [Orabug:
    26880517] (CVE-2017-7482) (CVE-2017-7482)

  - xen/mmu: Call xen_cleanhighmap with 4MB aligned for page
    tables mapping (Zhenzhong Duan) [Orabug: 26883322]

  - KVM: x86: fix deadlock in clock-in-progress request
    handling (Marcelo Tosatti) [Orabug: 27065995]

  - ocfs2: fstrim: Fix start offset of first cluster group
    during fstrim (Ashish Samant) [Orabug: 27099835]

  - USB: serial: console: fix use-after-free after failed
    setup (Johan Hovold) [Orabug: 27206837] (CVE-2017-16525)

  - uwb: properly check kthread_run return value (Andrey
    Konovalov) [Orabug: 27206897] (CVE-2017-16526)

  - ALSA: usb-audio: Check out-of-bounds access by corrupted
    buffer descriptor (Takashi Iwai) [Orabug: 27206928]
    (CVE-2017-16529)

  - USB: fix out-of-bounds in usb_set_configuration (Greg
    Kroah-Hartman) [Orabug: 27207240] (CVE-2017-16531)

  - USB: core: fix out-of-bounds access bug in
    usb_get_bos_descriptor (Alan Stern) [Orabug: 27207983]
    (CVE-2017-16535)

  - dccp: CVE-2017-8824: use-after-free in DCCP code
    (Mohamed Ghannam) [Orabug: 27290301] (CVE-2017-8824)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2018-May/000852.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-3.8.13-118.20.7.el6uek")) flag++;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-firmware-3.8.13-118.20.7.el6uek")) flag++;

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
