#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0370-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157938);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-28097",
    "CVE-2021-22600",
    "CVE-2021-39648",
    "CVE-2021-39657",
    "CVE-2021-39685",
    "CVE-2021-44733",
    "CVE-2021-45095",
    "CVE-2022-0286",
    "CVE-2022-0330",
    "CVE-2022-0435",
    "CVE-2022-22942"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/02");

  script_name(english:"openSUSE 15 Security Update : kernel (openSUSE-SU-2022:0370-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0370-1 advisory.

  - The vgacon subsystem in the Linux kernel before 5.8.10 mishandles software scrollback. There is a
    vgacon_scrolldelta out-of-bounds read, aka CID-973c096f6a85. (CVE-2020-28097)

  - A double free bug in packet_set_ring() in net/packet/af_packet.c can be exploited by a local user through
    crafted syscalls to escalate privileges or deny service. We recommend upgrading kernel past the effected
    versions or rebuilding past ec6af094ea28f0f2dda1a6a33b14cd57e36a9755 (CVE-2021-22600)

  - In gadget_dev_desc_UDC_show of configfs.c, there is a possible disclosure of kernel heap memory due to a
    race condition. This could lead to local information disclosure with System execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-160822094References: Upstream kernel (CVE-2021-39648)

  - In ufshcd_eh_device_reset_handler of ufshcd.c, there is a possible out of bounds read due to a missing
    bounds check. This could lead to local information disclosure with System execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-194696049References: Upstream kernel (CVE-2021-39657)

  - A use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel through 5.15.11.
    This occurs because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory
    object. (CVE-2021-44733)

  - pep_sock_accept in net/phonet/pep.c in the Linux kernel through 5.15.8 has a refcount leak.
    (CVE-2021-45095)

  - A flaw was found in the Linux kernel. A null pointer dereference in bond_ipsec_add_sa() may lead to local
    denial of service. (CVE-2022-0286)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195482");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ASMTCFCDULHGAOBQUFJH4PHVCQSTF7S6/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86b0c288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39648");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0330");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22942");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0435");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-al");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-allwinner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-altera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-amd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-amlogic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-apm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-broadcom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-cavium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-exynos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-freescale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-hisilicon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-mediatek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-qcom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-renesas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-rockchip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-socionext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-sprd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-xilinx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-zte");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-rebuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'cluster-md-kmp-64kb-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-default-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-preempt-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-preempt-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-64kb-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-default-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-preempt-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-preempt-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-al-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-allwinner-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-altera-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-amd-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-amlogic-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-apm-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-arm-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-broadcom-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-cavium-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-exynos-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-freescale-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-hisilicon-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-lg-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-marvell-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-mediatek-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-nvidia-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-qcom-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-renesas-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-rockchip-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-socionext-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-sprd-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-xilinx-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-zte-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-64kb-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-default-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-preempt-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-preempt-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-devel-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-extra-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-livepatch-devel-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-optional-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-livepatch-devel-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-base-5.3.18-150300.59.49.1.150300.18.31.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-base-rebuild-5.3.18-150300.59.49.1.150300.18.31.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-devel-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-extra-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-livepatch-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-optional-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-devel-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-livepatch-devel-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-macros-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-obs-build-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-obs-qa-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-extra-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-extra-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-livepatch-devel-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-livepatch-devel-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-optional-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-optional-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-vanilla-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-syms-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-5.3.18-150300.59.49.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-64kb-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-default-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-preempt-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-preempt-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-64kb-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-default-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-preempt-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-preempt-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-64kb-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.49.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-preempt-5.3.18-150300.59.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-preempt-5.3.18-150300.59.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-64kb / cluster-md-kmp-default / cluster-md-kmp-preempt / etc');
}
