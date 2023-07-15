#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0017.
#

include("compat.inc");

if (description)
{
  script_id(106706);
  script_version("3.4");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2017-0861", "CVE-2017-12193", "CVE-2017-14140", "CVE-2017-15115", "CVE-2017-17712", "CVE-2017-5754", "CVE-2017-8824");
  script_xref(name:"IAVA", value:"2018-A-0019");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0017) (Meltdown)");
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

  - drivers/char/mem.c: deny access in open operation when
    securelevel is set (Ethan Zhao) [Orabug: 27234850]
    [Orabug: 27234850]

  - hugetlb: fix nr_pmds accounting with shared page tables
    (Kirill A. Shutemov) [Orabug: 26988581]

  - x86/IBRS: Drop unnecessary WRITE_ONCE (Boris Ostrovsky)
    [Orabug: 27416198]

  - x86/IBRS: Don't try to change IBRS mode if IBRS is not
    available (Boris Ostrovsky) [Orabug: 27416198]

  - x86/IBRS: Remove support for IBRS_ENABLED_USER mode
    (Boris Ostrovsky) 

  - x86: Include linux/device.h in bugs_64.c (Boris
    Ostrovsky) [Orabug: 27418896]

  - x86/spectre: Drop the warning about ibrs being obsolete.
    (Konrad Rzeszutek Wilk)

  - x86/spec: Don't print the Missing arguments for option
    spectre_v2. (Konrad Rzeszutek Wilk)

  - x86/spec: Also print IBRS if IBPB is disabled. (Konrad
    Rzeszutek Wilk)

  - x86/IBPB: Provide debugfs interface for changing IBPB
    mode (Boris Ostrovsky) [Orabug: 27449065]

  - xen: Make PV Dom0 Linux kernel NUMA aware (Elena
    Ufimtseva)

  - net/rds: Fix incorrect error handling (H&aring kon
    Bugge) [Orabug: 26848729]

  - net/rds: use multiple sge than buddy allocation in
    congestion code (Wei Lin Guay) [Orabug: 26848729]

  - Revert 'RDS: fix the sg allocation based on actual
    message size' (Wei Lin Guay) [Orabug: 26848729]

  - Revert 'RDS: avoid large pages for sg allocation for TCP
    transport' (Wei Lin Guay) [Orabug: 26848729]

  - Revert 'net/rds: Reduce memory footprint in rds_sendmsg'
    (Wei Lin Guay) [Orabug: 26848729]

  - net/rds: reduce memory footprint during ib_post_recv in
    IB transport (Wei Lin Guay) [Orabug: 26848729]

  - net/rds: reduce memory footprint during rds_sendmsg with
    IB transport (Wei Lin Guay) [Orabug: 26848729]

  - net/rds: set the rds_ib_init_frag based on supported sge
    (Wei Lin Guay) [Orabug: 26848729]

  - bnxt_en: Fix possible corrupted NVRAM parameters from
    firmware response. (Michael Chan) [Orabug: 27199588]

  - x86, kasan: Fix build failure on KASAN=y && KMEMCHECK=y
    kernels (Andrey Ryabinin) [Orabug: 27255122]

  - x86, efi, kasan: Fix build failure on !KASAN &&
    KMEMCHECK=y kernels (Andrey Ryabinin) [Orabug: 27255122]

  - x86, efi, kasan: #undef memset/memcpy/memmove per arch
    (Andrey Ryabinin) [Orabug: 27255122]

  - Revert 'Makefile: Build with -Werror=date-time if the
    compiler supports it' (Gayatri Vasudevan) [Orabug:
    27255122]

  - dccp: CVE-2017-8824: use-after-free in DCCP code
    (Mohamed Ghannam) [Orabug: 27290300] (CVE-2017-8824)

  - x86/efi: Initialize and display UEFI secure boot state a
    bit later during init (Daniel Kiper) [Orabug: 27309477]

  - x86/espfix: Init espfix on the boot CPU side (Zhu
    Guihua) [Orabug: 27344552]

  - x86/espfix: Add 'cpu' parameter to init_espfix_ap (Zhu
    Guihua) 

  - ALSA: pcm: prevent UAF in snd_pcm_info (Robb Glasser)
    [Orabug: 27344841] (CVE-2017-0861) (CVE-2017-0861)

  - fs/ocfs2: remove page cache for converted direct write
    (Wengang Wang)

  - Revert 'ocfs2: code clean up for direct io' (Wengang
    Wang)

  - assoc_array: Fix a buggy node-splitting case (David
    Howells) [Orabug: 27364592] (CVE-2017-12193)
    (CVE-2017-12193)

  - Sanitize 'move_pages' permission checks (Linus Torvalds)
    [Orabug: 27364690] (CVE-2017-14140)

  - pti: compile fix for when PTI is disabled (Pavel
    Tatashin) [Orabug: 27383147] (CVE-2017-5754)

  - sctp: do not peel off an assoc from one netns to another
    one (Xin Long) [Orabug: 27386999] (CVE-2017-15115)

  - net: ipv4: fix for a race condition in raw_sendmsg
    (Mohamed Ghannam) [Orabug: 27390682] (CVE-2017-17712)

  - mlx4: add mstflint secure boot access kernel support
    (Qing Huang) 

  - x86: Move STUFF_RSB in to the idt macro (Konrad
    Rzeszutek Wilk)

  - x86/spec: STUFF_RSB _before_ ENABLE_IBRS (Konrad
    Rzeszutek Wilk)

  - x86: Move ENABLE_IBRS in the interrupt macro. (Konrad
    Rzeszutek Wilk)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-February/000828.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9702f90"
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-112.14.14.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-112.14.14.el6uek")) flag++;

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
