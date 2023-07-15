#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2019-0052.
#

include("compat.inc");

if (description)
{
  script_id(130923);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/13");

  script_cve_id("CVE-2018-12207", "CVE-2019-11135");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2019-0052)");
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

  - x86/tsx: Add config options to set tsx=on|off|auto
    (Michal Hocko) [Orabug: 30419233] (CVE-2019-11135)

  - x86/speculation/taa: Add documentation for TSX Async
    Abort (Pawan Gupta) [Orabug: 30419233] (CVE-2019-11135)

  - x86/tsx: Add 'auto' option to the tsx= cmdline parameter
    (Pawan Gupta) [Orabug: 30419233] (CVE-2019-11135)

  - kvm/x86: Export MDS_NO=0 to guests when TSX is enabled
    (Pawan Gupta) [Orabug: 30419233] (CVE-2019-11135)

  - x86/speculation/taa: Add sysfs reporting for TSX Async
    Abort (Pawan Gupta) [Orabug: 30419233] (CVE-2019-11135)

  - x86/speculation/taa: Add mitigation for TSX Async Abort
    (Kanth Ghatraju) [Orabug: 30419233] (CVE-2019-11135)

  - x86/cpu: Add a 'tsx=' cmdline option with TSX disabled
    by default (Pawan Gupta) [Orabug: 30419233]
    (CVE-2019-11135)

  - x86/cpu: Add a helper function x86_read_arch_cap_msr
    (Pawan Gupta) [Orabug: 30419233] (CVE-2019-11135)

  - x86/msr: Add the IA32_TSX_CTRL MSR (Pawan Gupta)
    [Orabug: 30419233] (CVE-2019-11135)

  - kvm: x86: mmu: Recovery of shattered NX large pages
    (Junaid Shahid) [Orabug: 29967631] (CVE-2018-12207)

  - kvm: Add helper function for creating VM worker threads
    (Junaid Shahid) [Orabug: 29967631] (CVE-2018-12207)

  - kvm: mmu: ITLB_MULTIHIT mitigation (Paolo Bonzini)
    [Orabug: 29967631] (CVE-2018-12207)

  - KVM: x86: remove now unneeded hugepage gfn adjustment
    (Paolo Bonzini) [Orabug: 29967631] (CVE-2018-12207)

  - KVM: x86: make FNAME(fetch) and __direct_map more
    similar (Paolo Bonzini) [Orabug: 29967631]
    (CVE-2018-12207)

  - kvm: x86: Do not release the page inside mmu_set_spte
    (Junaid Shahid) [Orabug: 29967631] (CVE-2018-12207)

  - x86/cpu: Add Tremont to the cpu vulnerability whitelist
    (Pawan Gupta) [Orabug: 29967631] (CVE-2018-12207)

  - x86: Add ITLB_MULTIHIT bug infrastructure (Pawan Gupta)
    [Orabug: 29967631] (CVE-2018-12207)

  - KVM: x86: MMU: Move mapping_level_dirty_bitmap call in
    mapping_level (Takuya Yoshikawa) [Orabug: 29967631]
    (CVE-2018-12207)

  - Revert 'KVM: x86: use the fast way to invalidate all
    pages' (Sean Christopherson) [Orabug: 29967631]
    (CVE-2018-12207)

  - kvm: Convert kvm_lock to a mutex (Junaid Shahid)
    [Orabug: 29967631] (CVE-2018-12207)

  - KVM: x86: MMU: Simplify force_pt_level calculation code
    in FNAME(page_fault) (Takuya Yoshikawa) [Orabug:
    29967631] (CVE-2018-12207)

  - KVM: x86: MMU: Make force_pt_level bool (Takuya
    Yoshikawa) [Orabug: 29967631] (CVE-2018-12207)

  - KVM: x86: MMU: Remove unused parameter parent_pte from
    kvm_mmu_get_page (Takuya Yoshikawa) [Orabug: 29967631]
    (CVE-2018-12207)

  - KVM: x86: extend usage of RET_MMIO_PF_* constants (Paolo
    Bonzini) [Orabug: 29967631] (CVE-2018-12207)

  - KVM: x86: MMU: Make mmu_set_spte return emulate value
    (Takuya Yoshikawa) [Orabug: 29967631] (CVE-2018-12207)

  - KVM: x86: MMU: Move parent_pte handling from
    kvm_mmu_get_page to link_shadow_page (Takuya Yoshikawa)
    [Orabug: 29967631] (CVE-2018-12207)

  - KVM: x86: MMU: Move initialization of parent_ptes out
    from kvm_mmu_alloc_page (Takuya Yoshikawa) [Orabug:
    29967631] (CVE-2018-12207)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2019-November/000966.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7baad653"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11135");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.32.3.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.32.3.2.el6uek")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
