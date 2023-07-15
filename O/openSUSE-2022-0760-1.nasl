#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0760-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158777);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/16");

  script_cve_id(
    "CVE-2022-0001",
    "CVE-2022-0002",
    "CVE-2022-0492",
    "CVE-2022-0516",
    "CVE-2022-0847",
    "CVE-2022-25375"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/16");

  script_name(english:"openSUSE 15 Security Update : kernel (openSUSE-SU-2022:0760-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0760-1 advisory.

  - Amazon Linux has been made aware of a potential Branch Target Injection (BTI) issue (sometimes referred to
    as Spectre variant 2). This is a known cross-domain transient execution attack where a third party may
    seek to cause a disclosure gadget to be speculatively executed after an indirect branch prediction.
    Generally, actors who attempt transient execution attacks do not have access to the data on the hosts they
    attempt to access (e.g. where privilege-level isolation is in place). For such attacks to succeed, actors
    need to be able to run code on the (virtual) machine hosting the data in which they are interested.
    (CVE-2022-0001, CVE-2022-0002, CVE-2022-0847)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - kernel: missing check in ioctl allows kernel memory read/write (CVE-2022-0516)

  - An issue was discovered in drivers/usb/gadget/function/rndis.c in the Linux kernel before 5.16.10. The
    RNDIS USB gadget lacks validation of the size of the RNDIS_MSG_SET command. Attackers can obtain sensitive
    information from kernel memory. (CVE-2022-25375)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1089644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195352");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196776");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GIEQJF6RAZADJBWJQFLIHOBULB4E2C7K/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af960ba2");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0492");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-25375");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0847");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Dirty Pipe Local Privilege Escalation via CVE-2022-0847');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-km64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmdefault");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmpreempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-km64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmdefault");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmpreempt");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-km64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmdefault");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmpreempt");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-km64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmdefault");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmpreempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-km64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmdefault");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmpreempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-km64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmdefault");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmpreempt");
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
    {'reference':'cluster-md-kmp-64kb-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-default-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-preempt-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-preempt-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-64kb-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-default-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-preempt-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-preempt-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-al-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-allwinner-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-altera-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-amd-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-amlogic-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-apm-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-arm-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-broadcom-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-cavium-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-exynos-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-freescale-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-hisilicon-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-lg-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-marvell-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-mediatek-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-nvidia-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-qcom-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-renesas-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-rockchip-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-socionext-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-sprd-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-xilinx-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-zte-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-64kb-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-default-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-preempt-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-preempt-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-devel-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-extra-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-livepatch-devel-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-optional-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-livepatch-devel-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-base-5.3.18-150300.59.54.1.150300.18.35.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-base-rebuild-5.3.18-150300.59.54.1.150300.18.35.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-devel-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-extra-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-livepatch-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-optional-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-devel-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-livepatch-devel-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-macros-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-obs-build-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-obs-qa-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-extra-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-extra-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-livepatch-devel-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-livepatch-devel-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-optional-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-optional-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-vanilla-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-syms-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-5.3.18-150300.59.54.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-64kb-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-default-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-preempt-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-preempt-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-64kb-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-default-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-preempt-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-preempt-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-64kb-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-preempt-5.3.18-150300.59.54.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-preempt-5.3.18-150300.59.54.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
