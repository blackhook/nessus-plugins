#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:0146-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170674);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_cve_id(
    "CVE-2022-3104",
    "CVE-2022-3105",
    "CVE-2022-3106",
    "CVE-2022-3107",
    "CVE-2022-3108",
    "CVE-2022-3111",
    "CVE-2022-3112",
    "CVE-2022-3113",
    "CVE-2022-3114",
    "CVE-2022-3115",
    "CVE-2022-3344",
    "CVE-2022-3564",
    "CVE-2022-4379",
    "CVE-2022-4662",
    "CVE-2022-47520"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:0146-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2023:0146-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:0146-1 advisory.

  - An issue was discovered in the Linux kernel through 5.16-rc6. lkdtm_ARRAY_BOUNDS in
    drivers/misc/lkdtm/bugs.c lacks check of the return value of kmalloc() and will cause the null pointer
    dereference. (CVE-2022-3104)

  - An issue was discovered in the Linux kernel through 5.16-rc6. uapi_finalize in
    drivers/infiniband/core/uverbs_uapi.c lacks check of kmalloc_array(). (CVE-2022-3105)

  - An issue was discovered in the Linux kernel through 5.16-rc6. ef100_update_stats in
    drivers/net/ethernet/sfc/ef100_nic.c lacks check of the return value of kmalloc(). (CVE-2022-3106)

  - An issue was discovered in the Linux kernel through 5.16-rc6. netvsc_get_ethtool_stats in
    drivers/net/hyperv/netvsc_drv.c lacks check of the return value of kvmalloc_array() and will cause the
    null pointer dereference. (CVE-2022-3107)

  - An issue was discovered in the Linux kernel through 5.16-rc6. kfd_parse_subtype_iolink in
    drivers/gpu/drm/amd/amdkfd/kfd_crat.c lacks check of the return value of kmemdup(). (CVE-2022-3108)

  - An issue was discovered in the Linux kernel through 5.16-rc6. free_charger_irq() in
    drivers/power/supply/wm8350_power.c lacks free of WM8350_IRQ_CHG_FAST_RDY, which is registered in
    wm8350_init_charger(). (CVE-2022-3111)

  - An issue was discovered in the Linux kernel through 5.16-rc6. amvdec_set_canvases in
    drivers/staging/media/meson/vdec/vdec_helpers.c lacks check of the return value of kzalloc() and will
    cause the null pointer dereference. (CVE-2022-3112)

  - An issue was discovered in the Linux kernel through 5.16-rc6. mtk_vcodec_fw_vpu_init in
    drivers/media/platform/mtk-vcodec/mtk_vcodec_fw_vpu.c lacks check of the return value of devm_kzalloc()
    and will cause the null pointer dereference. (CVE-2022-3113)

  - An issue was discovered in the Linux kernel through 5.16-rc6. imx_register_uart_clocks in
    drivers/clk/imx/clk.c lacks check of the return value of kcalloc() and will cause the null pointer
    dereference. (CVE-2022-3114)

  - An issue was discovered in the Linux kernel through 5.16-rc6. malidp_crtc_reset in
    drivers/gpu/drm/arm/malidp_crtc.c lacks check of the return value of kzalloc() and will cause the null
    pointer dereference. (CVE-2022-3115)

  - A flaw was found in the KVM's AMD nested virtualization (SVM). A malicious L1 guest could purposely fail
    to intercept the shutdown of a cooperative nested guest (L2), possibly leading to a page fault and kernel
    panic in the host (L0). (CVE-2022-3344)

  - A vulnerability classified as critical was found in Linux Kernel. Affected by this vulnerability is the
    function l2cap_reassemble_sdu of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The associated
    identifier of this vulnerability is VDB-211087. (CVE-2022-3564)

  - A use-after-free vulnerability was found in __nfs42_ssc_open() in fs/nfs/nfs4file.c in the Linux kernel.
    This flaw allows an attacker to conduct a remote denial (CVE-2022-4379)

  - A flaw incorrect access control in the Linux kernel USB core subsystem was found in the way user attaches
    usb device. A local user could use this flaw to crash the system. (CVE-2022-4662)

  - An issue was discovered in the Linux kernel before 6.0.11. Missing offset validation in
    drivers/net/wireless/microchip/wilc1000/hif.c in the WILC1000 wireless driver can trigger an out-of-bounds
    read when parsing a Robust Security Network (RSN) information element from a Netlink packet.
    (CVE-2022-47520)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207016");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-January/013527.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67b04e7a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3105");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3107");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3108");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3111");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3112");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3113");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3115");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3344");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3564");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4379");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-47520");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3564");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-47520");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-5.14.21-150400.14.31.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.31.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.31.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.31.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-devel-azure-5.14.21-150400.14.31.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-source-azure-5.14.21-150400.14.31.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.31.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.31.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150400.14.31.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150400.14.31.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-azure-5.14.21-150400.14.31.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-azure-5.14.21-150400.14.31.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-azure-5.14.21-150400.14.31.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-azure-5.14.21-150400.14.31.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.31.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.31.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.31.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.31.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-extra-5.14.21-150400.14.31.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-extra-5.14.21-150400.14.31.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150400.14.31.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150400.14.31.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-optional-5.14.21-150400.14.31.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-optional-5.14.21-150400.14.31.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-devel-azure-5.14.21-150400.14.31.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-source-azure-5.14.21-150400.14.31.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.31.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.31.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kselftests-kmp-azure-5.14.21-150400.14.31.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kselftests-kmp-azure-5.14.21-150400.14.31.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150400.14.31.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150400.14.31.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150400.14.31.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150400.14.31.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-azure / dlm-kmp-azure / gfs2-kmp-azure / kernel-azure / etc');
}
