##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0328. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(133477);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2019-14814",
    "CVE-2019-14815",
    "CVE-2019-14816",
    "CVE-2019-14895",
    "CVE-2019-14898",
    "CVE-2019-14901",
    "CVE-2019-17666",
    "CVE-2019-19338"
  );
  script_xref(name:"RHSA", value:"2020:0328");

  script_name(english:"RHEL 8 : kernel-rt (RHSA-2020:0328)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:0328 advisory.

  - kernel: heap overflow in mwifiex_set_uap_rates() function of Marvell Wifi Driver leading to DoS
    (CVE-2019-14814)

  - kernel: heap-overflow in mwifiex_set_wmm_params() function of Marvell WiFi driver leading to DoS
    (CVE-2019-14815)

  - kernel: heap overflow in mwifiex_update_vs_ie() function of Marvell WiFi driver (CVE-2019-14816)

  - kernel: heap-based buffer overflow in mwifiex_process_country_ie() function in
    drivers/net/wireless/marvell/mwifiex/sta_ioctl.c (CVE-2019-14895)

  - kernel: incomplete fix  for race condition between mmget_not_zero()/get_task_mm() and core dumping in
    CVE-2019-11599 (CVE-2019-14898)

  - kernel: heap overflow in marvell/mwifiex/tdls.c (CVE-2019-14901)

  - kernel: rtl_p2p_noa_ie in drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux kernel lacks a certain
    upper-bound check, leading to a buffer overflow (CVE-2019-17666)

  - Kernel: KVM: export MSR_IA32_TSX_CTRL to guest - incomplete fix for TAA (CVE-2019-11135) (CVE-2019-19338)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14814");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14815");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14816");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14895");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14898");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14901");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17666");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19338");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1744130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1744137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1744149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1763690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1773519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1781514");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14901");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120, 122, 203, 362, 385, 400, 667);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2019-14814', 'CVE-2019-14815', 'CVE-2019-14816', 'CVE-2019-14895', 'CVE-2019-14898', 'CVE-2019-14901', 'CVE-2019-17666', 'CVE-2019-19338');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2020:0328');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.2/x86_64/appstream/debug',
      'content/aus/rhel8/8.2/x86_64/appstream/os',
      'content/aus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.2/x86_64/baseos/debug',
      'content/aus/rhel8/8.2/x86_64/baseos/os',
      'content/aus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/appstream/debug',
      'content/e4s/rhel8/8.2/x86_64/appstream/os',
      'content/e4s/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/baseos/debug',
      'content/e4s/rhel8/8.2/x86_64/baseos/os',
      'content/e4s/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.2/x86_64/highavailability/os',
      'content/e4s/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sap/debug',
      'content/e4s/rhel8/8.2/x86_64/sap/os',
      'content/e4s/rhel8/8.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/appstream/debug',
      'content/eus/rhel8/8.2/x86_64/appstream/os',
      'content/eus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/baseos/debug',
      'content/eus/rhel8/8.2/x86_64/baseos/os',
      'content/eus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/highavailability/debug',
      'content/eus/rhel8/8.2/x86_64/highavailability/os',
      'content/eus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sap/debug',
      'content/eus/rhel8/8.2/x86_64/sap/os',
      'content/eus/rhel8/8.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/supplementary/debug',
      'content/eus/rhel8/8.2/x86_64/supplementary/os',
      'content/eus/rhel8/8.2/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/appstream/debug',
      'content/tus/rhel8/8.2/x86_64/appstream/os',
      'content/tus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/baseos/debug',
      'content/tus/rhel8/8.2/x86_64/baseos/os',
      'content/tus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/highavailability/debug',
      'content/tus/rhel8/8.2/x86_64/highavailability/os',
      'content/tus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/nfv/debug',
      'content/tus/rhel8/8.2/x86_64/nfv/os',
      'content/tus/rhel8/8.2/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/rt/debug',
      'content/tus/rhel8/8.2/x86_64/rt/os',
      'content/tus/rhel8/8.2/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.4/x86_64/appstream/debug',
      'content/aus/rhel8/8.4/x86_64/appstream/os',
      'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.4/x86_64/baseos/debug',
      'content/aus/rhel8/8.4/x86_64/baseos/os',
      'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/appstream/debug',
      'content/e4s/rhel8/8.4/x86_64/appstream/os',
      'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/baseos/debug',
      'content/e4s/rhel8/8.4/x86_64/baseos/os',
      'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.4/x86_64/highavailability/os',
      'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap/debug',
      'content/e4s/rhel8/8.4/x86_64/sap/os',
      'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/appstream/debug',
      'content/eus/rhel8/8.4/x86_64/appstream/os',
      'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/baseos/debug',
      'content/eus/rhel8/8.4/x86_64/baseos/os',
      'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/highavailability/debug',
      'content/eus/rhel8/8.4/x86_64/highavailability/os',
      'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap/debug',
      'content/eus/rhel8/8.4/x86_64/sap/os',
      'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/supplementary/debug',
      'content/eus/rhel8/8.4/x86_64/supplementary/os',
      'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/appstream/debug',
      'content/tus/rhel8/8.4/x86_64/appstream/os',
      'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/baseos/debug',
      'content/tus/rhel8/8.4/x86_64/baseos/os',
      'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/highavailability/debug',
      'content/tus/rhel8/8.4/x86_64/highavailability/os',
      'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/nfv/debug',
      'content/tus/rhel8/8.4/x86_64/nfv/os',
      'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/rt/debug',
      'content/tus/rhel8/8.4/x86_64/rt/os',
      'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.6/x86_64/appstream/debug',
      'content/aus/rhel8/8.6/x86_64/appstream/os',
      'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.6/x86_64/baseos/debug',
      'content/aus/rhel8/8.6/x86_64/baseos/os',
      'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/appstream/debug',
      'content/e4s/rhel8/8.6/x86_64/appstream/os',
      'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/baseos/debug',
      'content/e4s/rhel8/8.6/x86_64/baseos/os',
      'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.6/x86_64/highavailability/os',
      'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap/debug',
      'content/e4s/rhel8/8.6/x86_64/sap/os',
      'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/appstream/debug',
      'content/eus/rhel8/8.6/x86_64/appstream/os',
      'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/baseos/debug',
      'content/eus/rhel8/8.6/x86_64/baseos/os',
      'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/highavailability/debug',
      'content/eus/rhel8/8.6/x86_64/highavailability/os',
      'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap/debug',
      'content/eus/rhel8/8.6/x86_64/sap/os',
      'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/supplementary/debug',
      'content/eus/rhel8/8.6/x86_64/supplementary/os',
      'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/appstream/debug',
      'content/tus/rhel8/8.6/x86_64/appstream/os',
      'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/baseos/debug',
      'content/tus/rhel8/8.6/x86_64/baseos/os',
      'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/highavailability/debug',
      'content/tus/rhel8/8.6/x86_64/highavailability/os',
      'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/rt/os',
      'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/highavailability/debug',
      'content/dist/rhel8/8/x86_64/highavailability/os',
      'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/x86_64/nfv/debug',
      'content/dist/rhel8/8/x86_64/nfv/os',
      'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8/x86_64/resilientstorage/os',
      'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/x86_64/rt/debug',
      'content/dist/rhel8/8/x86_64/rt/os',
      'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap-solutions/debug',
      'content/dist/rhel8/8/x86_64/sap-solutions/os',
      'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap/debug',
      'content/dist/rhel8/8/x86_64/sap/os',
      'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
      'content/dist/rhel8/8/x86_64/supplementary/debug',
      'content/dist/rhel8/8/x86_64/supplementary/os',
      'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-4.18.0-147.5.1.rt24.98.el8_1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-4.18.0-147.5.1.rt24.98.el8_1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-4.18.0-147.5.1.rt24.98.el8_1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-4.18.0-147.5.1.rt24.98.el8_1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-4.18.0-147.5.1.rt24.98.el8_1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-4.18.0-147.5.1.rt24.98.el8_1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-4.18.0-147.5.1.rt24.98.el8_1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-4.18.0-147.5.1.rt24.98.el8_1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-4.18.0-147.5.1.rt24.98.el8_1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-4.18.0-147.5.1.rt24.98.el8_1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-4.18.0-147.5.1.rt24.98.el8_1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-4.18.0-147.5.1.rt24.98.el8_1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/e4s/rhel8/8.1/x86_64/appstream/debug',
      'content/e4s/rhel8/8.1/x86_64/appstream/os',
      'content/e4s/rhel8/8.1/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.1/x86_64/baseos/debug',
      'content/e4s/rhel8/8.1/x86_64/baseos/os',
      'content/e4s/rhel8/8.1/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.1/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.1/x86_64/highavailability/os',
      'content/e4s/rhel8/8.1/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.1/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.1/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.1/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.1/x86_64/sap/debug',
      'content/e4s/rhel8/8.1/x86_64/sap/os',
      'content/e4s/rhel8/8.1/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.1/x86_64/appstream/debug',
      'content/eus/rhel8/8.1/x86_64/appstream/os',
      'content/eus/rhel8/8.1/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.1/x86_64/baseos/debug',
      'content/eus/rhel8/8.1/x86_64/baseos/os',
      'content/eus/rhel8/8.1/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.1/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.1/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.1/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.1/x86_64/highavailability/debug',
      'content/eus/rhel8/8.1/x86_64/highavailability/os',
      'content/eus/rhel8/8.1/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.1/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.1/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.1/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.1/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.1/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.1/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.1/x86_64/sap/debug',
      'content/eus/rhel8/8.1/x86_64/sap/os',
      'content/eus/rhel8/8.1/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.1/x86_64/supplementary/debug',
      'content/eus/rhel8/8.1/x86_64/supplementary/os',
      'content/eus/rhel8/8.1/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-4.18.0-147.5.1.rt24.98.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp']) && !enterprise_linux_flag) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-core / kernel-rt-debug / kernel-rt-debug-core / etc');
}
