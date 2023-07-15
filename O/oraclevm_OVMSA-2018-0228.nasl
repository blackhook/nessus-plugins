#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0228.
#

include("compat.inc");

if (description)
{
  script_id(110526);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2017-16939", "CVE-2018-1000199", "CVE-2018-3639");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0228) (Spectre)");
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

  - netlink: add a start callback for starting a netlink
    dump (Tom Herbert) [Orabug: 27169581] (CVE-2017-16939)

  - ipsec: Fix aborted xfrm policy dump crash (Herbert Xu)
    [Orabug: 27169581] (CVE-2017-16939)

  - net/rds: prevent RDS connections using stale ARP entries
    (Wei Lin Guay) [Orabug: 28149101]

  - net/rds: Avoid stalled connection due to CM REQ retries
    (Wei Lin Guay) [Orabug: 28068627]

  - net/rds: use one sided reconnection during a race (Wei
    Lin Guay) 

  - Revert 'Revert 'net/rds: Revert 'RDS: add reconnect
    retry scheme for stalled' (H&aring kon Bugge) [Orabug:
    28068627]

  - xen-swiotlb: fix the check condition for
    xen_swiotlb_free_coherent (Joe Jin) [Orabug: 22910685]

  - net/rds: Assign the correct service level (Wei Lin Guay)
    [Orabug: 27607213]

  - target: Re-add missing SCF_ACK_KREF assignment in v4.1.y
    (Nicholas Bellinger) [Orabug: 27781132]

  - target: Fix LUN_RESET active I/O handling for ACK_KREF
    (Nicholas Bellinger) [Orabug: 27781132]

  - target: Invoke release_cmd callback without holding a
    spinlock (Bart Van Assche) [Orabug: 27781132]

  - x86/bugs: Remove the Disabling Spectre v2 mitigation
    retpoline (Konrad Rzeszutek Wilk) [Orabug: 27897282]

  - x86/bugs: Report properly retpoline+IBRS (Konrad
    Rzeszutek Wilk)

  - x86/bugs: Don't lie when fallback retpoline is engaged
    (Konrad Rzeszutek Wilk)

  - fs: aio: fix the increment of aio-nr and counting
    against aio-max-nr (Mauricio Faria de Oliveira) [Orabug:
    28079082]

  - qla2xxx: Enable buffer boundary check when DIF bundling
    is on. (Rajan Shanmugavelu) [Orabug: 28130589]

  - kernel: sys.c: missing break for prctl spec ctrl (Mihai
    Carabas) 

  - x86/bugs/IBRS: Keep SSBD mitigation in effect if
    spectre_v2=ibrs is selected (Mihai Carabas)

  - fs/pstore: update the backend parameter in pstore module
    (Wang Long) 

  - kvm: vmx: Reinstate support for CPUs without virtual NMI
    (Paolo Bonzini) [Orabug: 28041210]

  - dm crypt: add big-endian variant of plain64 IV (Milan
    Broz) [Orabug: 28043932]

  - x86/bugs: Rename SSBD_NO to SSB_NO (Konrad Rzeszutek
    Wilk) [Orabug: 28063992] (CVE-2018-3639)

  - KVM: SVM: Implement VIRT_SPEC_CTRL support for SSBD (Tom
    Lendacky) [Orabug: 28063992] [Orabug: 28069548]
    (CVE-2018-3639)

  - x86/speculation, KVM: Implement support for
    VIRT_SPEC_CTRL/LS_CFG (Thomas Gleixner) [Orabug:
    28063992] (CVE-2018-3639)

  - x86/bugs: Rework spec_ctrl base and mask logic (Thomas
    Gleixner) [Orabug: 28063992] (CVE-2018-3639)

  - x86/bugs: Expose x86_spec_ctrl_base directly (Thomas
    Gleixner) [Orabug: 28063992] (CVE-2018-3639)

  - x86/bugs: Unify x86_spec_ctrl_[set_guest,restore_host]
    (Borislav Petkov) [Orabug: 28063992] (CVE-2018-3639)

  - x86/speculation: Rework speculative_store_bypass_update
    (Thomas Gleixner) [Orabug: 28063992] (CVE-2018-3639)

  - x86/speculation: Add virtualized speculative store
    bypass disable support (Tom Lendacky) [Orabug: 28063992]
    (CVE-2018-3639)

  - x86/bugs, KVM: Extend speculation control for
    VIRT_SPEC_CTRL (Thomas Gleixner) [Orabug: 28063992]
    (CVE-2018-3639)

  - x86/speculation: Handle HT correctly on AMD (Thomas
    Gleixner) [Orabug: 28063992] (CVE-2018-3639)

  - x86/cpufeatures: Add FEATURE_ZEN (Thomas Gleixner)
    [Orabug: 28063992] (CVE-2018-3639)

  - x86/cpu/AMD: Fix erratum 1076 (CPB bit) (Borislav
    Petkov) [Orabug: 28063992] (CVE-2018-3639)

  - perf/hwbp: Simplify the perf-hwbp code, fix
    documentation (Linus Torvalds) [Orabug: 27947602]
    (CVE-2018-1000199)

  - Revert 'perf/hwbp: Simplify the perf-hwbp code, fix
    documentation' (Brian Maly) [Orabug: 27947602]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2018-June/000863.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/14");
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
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.16.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.16.2.el6uek")) flag++;

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
