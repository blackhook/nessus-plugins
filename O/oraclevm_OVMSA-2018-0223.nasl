#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0223.
#

include("compat.inc");

if (description)
{
  script_id(110072);
  script_version("1.5");
  script_cvs_date("Date: 2020/01/23");

  script_cve_id("CVE-2017-1000410", "CVE-2017-18203", "CVE-2018-10323", "CVE-2018-10675", "CVE-2018-3639", "CVE-2018-5333", "CVE-2018-5750", "CVE-2018-6927", "CVE-2018-8781");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0223) (Spectre)");
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

  - KVM: SVM: Move spec control call after restore of GS
    (Thomas Gleixner) (CVE-2018-3639)

  - x86/bugs: Fix the parameters alignment and missing void
    (Konrad Rzeszutek Wilk) (CVE-2018-3639)

  - x86/bugs: Make cpu_show_common static (Jiri Kosina)
    (CVE-2018-3639)

  - x86/bugs: Fix __ssb_select_mitigation return type (Jiri
    Kosina) (CVE-2018-3639)

  - Documentation/spec_ctrl: Do some minor cleanups
    (Borislav Petkov) (CVE-2018-3639)

  - proc: Use underscores for SSBD in 'status' (Konrad
    Rzeszutek Wilk) (CVE-2018-3639)

  - x86/bugs: Rename _RDS to _SSBD (Konrad Rzeszutek Wilk)
    (CVE-2018-3639)

  - x86/speculation: Make 'seccomp' the default mode for
    Speculative Store Bypass (Kees Cook) (CVE-2018-3639)

  - seccomp: Move speculation migitation control to arch
    code (Thomas Gleixner) (CVE-2018-3639)

  - seccomp: Add filter flag to opt-out of SSB mitigation
    (Kees Cook) (CVE-2018-3639)

  - seccomp: Use PR_SPEC_FORCE_DISABLE (Thomas Gleixner)
    (CVE-2018-3639)

  - prctl: Add force disable speculation (Konrad Rzeszutek
    Wilk) (CVE-2018-3639)

  - seccomp: Enable speculation flaw mitigations (Kees Cook)
    (CVE-2018-3639)

  - proc: Provide details on speculation flaw mitigations
    (Kees Cook) (CVE-2018-3639)

  - nospec: Allow getting/setting on non-current task (Kees
    Cook) (CVE-2018-3639)

  - x86/bugs/IBRS: Disable SSB (RDS) if IBRS is sslected for
    spectre_v2. (Konrad Rzeszutek Wilk) (CVE-2018-3639)

  - x86/speculation: Add prctl for Speculative Store Bypass
    mitigation (Thomas Gleixner) (CVE-2018-3639)

  - x86: thread_info.h: move RDS from index 5 to 23 (Mihai
    Carabas) (CVE-2018-3639)

  - x86/process: Allow runtime control of Speculative Store
    Bypass (Thomas Gleixner) (CVE-2018-3639)

  - prctl: Add speculation control prctls (Thomas Gleixner)
    (CVE-2018-3639)

  - x86/speculation: Create spec-ctrl.h to avoid include
    hell (Thomas Gleixner) (CVE-2018-3639)

  - x86/KVM/VMX: Expose SPEC_CTRL Bit(2) to the guest
    (Konrad Rzeszutek Wilk) (CVE-2018-3639)

  - x86/bugs/AMD: Add support to disable RDS on
    Fam[15,16,17]h if requested (Konrad Rzeszutek Wilk)
    (CVE-2018-3639)

  - x86/bugs: Whitelist allowed SPEC_CTRL MSR values (Konrad
    Rzeszutek Wilk) (CVE-2018-3639)

  - x86/bugs/intel: Set proper CPU features and setup RDS
    (Konrad Rzeszutek Wilk) (CVE-2018-3639)

  - x86/bugs: Provide boot parameters for the
    spec_store_bypass_disable mitigation (Konrad Rzeszutek
    Wilk) (CVE-2018-3639)

  - x86/cpufeatures: Add X86_FEATURE_RDS (Konrad Rzeszutek
    Wilk) (CVE-2018-3639)

  - x86/bugs: Expose /sys/../spec_store_bypass (Konrad
    Rzeszutek Wilk) (CVE-2018-3639)

  - x86/cpu/intel: Add Knights Mill to Intel family (Piotr
    Luc) (CVE-2018-3639)

  - x86/cpu: Rename Merrifield2 to Moorefield (Andy
    Shevchenko) (CVE-2018-3639)

  - x86/bugs, KVM: Support the combination of guest and host
    IBRS (Konrad Rzeszutek Wilk) (CVE-2018-3639)

  - x86/bugs/IBRS: Warn if IBRS is enabled during boot.
    (Konrad Rzeszutek Wilk) (CVE-2018-3639)

  - x86/bugs/IBRS: Use variable instead of defines for
    enabling IBRS (Konrad Rzeszutek Wilk) (CVE-2018-3639)

  - x86/bugs: Read SPEC_CTRL MSR during boot and re-use
    reserved bits (Konrad Rzeszutek Wilk) (CVE-2018-3639)

  - x86/bugs: Concentrate bug reporting into a separate
    function (Konrad Rzeszutek Wilk) (CVE-2018-3639)

  - x86/bugs: Concentrate bug detection into a separate
    function (Konrad Rzeszutek Wilk) (CVE-2018-3639)

  - x86/bugs/IBRS: Turn on IBRS in
    spectre_v2_select_mitigation (Konrad Rzeszutek Wilk)
    (CVE-2018-3639)

  - x86/msr: Add SPEC_CTRL_IBRS.. (Konrad Rzeszutek Wilk)
    (CVE-2018-3639)

  - scsi: libfc: Revisit kref handling (Hannes Reinecke)

  - scsi: libfc: reset exchange manager during LOGO handling
    (Hannes Reinecke)

  - scsi: libfc: send LOGO for PLOGI failure (Hannes
    Reinecke)

  - scsi: libfc: Issue PRLI after a PRLO has been received
    (Hannes Reinecke)

  - libfc: Update rport reference counting (Hannes Reinecke)

  - amd/kvm: do not intercept new MSRs for spectre v2
    mitigation (Elena Ufimtseva)

  - RDS: null pointer dereference in rds_atomic_free_op
    (Mohamed Ghannam) [Orabug: 27422832] (CVE-2018-5333)

  - ACPI: sbshc: remove raw pointer from printk message
    (Greg Kroah-Hartman) [Orabug: 27501257] (CVE-2018-5750)

  - futex: Prevent overflow by strengthen input validation
    (Li Jinyue) [Orabug: 27539548] (CVE-2018-6927)

  - net: ipv4: add support for ECMP hash policy choice
    (Venkat Venkatsubra) [Orabug: 27547114]

  - net: ipv4: Consider failed nexthops in multipath routes
    (David Ahern) 

  - ipv4: L3 hash-based multipath (Peter N&oslash rlund)
    [Orabug: 27547114]

  - dm: fix race between dm_get_from_kobject and
    __dm_destroy (Hou Tao) [Orabug: 27677556]
    (CVE-2017-18203)

  - NFS: only invalidate dentrys that are clearly invalid.
    (NeilBrown) 

  - net: Improve handling of failures on link and route
    dumps (David Ahern) [Orabug: 27959177]

  - mm/mempolicy: fix use after free when calling
    get_mempolicy (zhong jiang) [Orabug: 27963519]
    (CVE-2018-10675)

  - drm: udl: Properly check framebuffer mmap offsets (Greg
    Kroah-Hartman) [Orabug: 27963530] (CVE-2018-8781)

  - xfs: set format back to extents if
    xfs_bmap_extents_to_btree (Eric Sandeen) [Orabug:
    27963576] (CVE-2018-10323)

  - Revert 'mlx4: change the ICM table allocations to lowest
    needed size' (H&aring kon Bugge) [Orabug: 27980030]

  - Bluetooth: Prevent stack info leak from the EFS element.
    (Ben Seri) [Orabug: 28030514] (CVE-2017-1000410)
    (CVE-2017-1000410)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2018-May/000858.html"
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
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.15.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.15.2.el6uek")) flag++;

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
