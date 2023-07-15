##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2854. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143086);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2018-16884",
    "CVE-2019-9458",
    "CVE-2019-11811",
    "CVE-2019-15917",
    "CVE-2019-18808",
    "CVE-2019-19062",
    "CVE-2019-19767",
    "CVE-2019-20636",
    "CVE-2020-8834",
    "CVE-2020-10720",
    "CVE-2020-11565",
    "CVE-2020-12888"
  );
  script_bugtraq_id(106253, 108410);
  script_xref(name:"RHSA", value:"2020:2854");

  script_name(english:"RHEL 7 : kernel-alt (RHSA-2020:2854)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:2854 advisory.

  - kernel: nfs: use-after-free in svc_process_common() (CVE-2018-16884)

  - kernel: use-after-free in drivers/char/ipmi/ipmi_si_intf.c, ipmi_si_mem_io.c, ipmi_si_port_io.c
    (CVE-2019-11811)

  - kernel: use-after-free in drivers/bluetooth/hci_ldisc.c (CVE-2019-15917)

  - kernel: memory leak in ccp_run_sha_cmd() function in drivers/crypto/ccp/ccp-ops.c (CVE-2019-18808)

  - kernel: memory leak in the crypto_report() function in crypto/crypto_user_base.c allows for DoS
    (CVE-2019-19062)

  - kernel: use-after-free in __ext4_expand_extra_isize and ext4_xattr_set_entry related to fs/ext4/inode.c
    and fs/ext4/super.c (CVE-2019-19767)

  - kernel: out-of-bounds write via crafted keycode table (CVE-2019-20636)

  - kernel: use after free due to race condition in the video driver leads to local privilege escalation
    (CVE-2019-9458)

  - kernel: use-after-free read in napi_gro_frags() in the Linux kernel (CVE-2020-10720)

  - kernel: out-of-bounds write in mpol_parse_str function in mm/mempolicy.c (CVE-2020-11565)

  - Kernel: vfio: access to disabled MMIO space of some devices may lead to DoS scenario (CVE-2020-12888)

  - Kernel: ppc: kvm: conflicting use of HSTATE_HOST_R1 to store r1 state leads to host stack corruption
    (CVE-2020-8834)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16884");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9458");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11811");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15917");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18808");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19062");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19767");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20636");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8834");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10720");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11565");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12888");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:2854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1660375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1709180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1777418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1781204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1786160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1819377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1819615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1824059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1824918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1836244");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20636");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-16884");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 248, 362, 400, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2018-16884', 'CVE-2019-9458', 'CVE-2019-11811', 'CVE-2019-15917', 'CVE-2019-18808', 'CVE-2019-19062', 'CVE-2019-19767', 'CVE-2019-20636', 'CVE-2020-8834', 'CVE-2020-10720', 'CVE-2020-11565', 'CVE-2020-12888');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2020:2854');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/os',
      'content/dist/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/debug',
      'content/dist/rhel/power/7/7Server/ppc64/sap/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/debug',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/os',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/os',
      'content/fastrack/rhel/power/7/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/os',
      'content/fastrack/rhel/power/7/ppc64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-abi-whitelists-4.14.0-115.26.1.el7a', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-4.14.0-115.26.1.el7a', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
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
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-abi-whitelists / kernel-bootwrapper / kernel-debug / etc');
}
