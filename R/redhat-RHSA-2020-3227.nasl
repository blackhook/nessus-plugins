##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3227. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(139192);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2020-10713",
    "CVE-2020-14308",
    "CVE-2020-14309",
    "CVE-2020-14310",
    "CVE-2020-14311",
    "CVE-2020-15705",
    "CVE-2020-15706",
    "CVE-2020-15707"
  );
  script_xref(name:"RHSA", value:"2020:3227");
  script_xref(name:"IAVA", value:"2020-A-0349");
  script_xref(name:"CEA-ID", value:"CEA-2020-0061");

  script_name(english:"RHEL 8 : grub2 (RHSA-2020:3227)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:3227 advisory.

  - grub2: Crafted grub.cfg file can lead to arbitrary code execution during boot process (CVE-2020-10713)

  - grub2: grub_malloc does not validate allocation size allowing for arithmetic overflow and subsequent heap-
    based buffer overflow (CVE-2020-14308)

  - grub2: Integer overflow in grub_squash_read_symlink may lead to heap-based buffer overflow
    (CVE-2020-14309)

  - grub2: Integer overflow read_section_as_string may lead to heap-based buffer overflow (CVE-2020-14310)

  - grub2: Integer overflow in grub_ext2_read_link leads to heap-based buffer overflow (CVE-2020-14311)

  - grub2: Fail kernel validation without shim protocol (CVE-2020-15705)

  - grub2: Use-after-free redefining a function whilst the same function is already executing (CVE-2020-15706)

  - grub2: Integer overflow in initrd size handling (CVE-2020-15707)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10713");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14308");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14309");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14310");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14311");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-15705");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-15706");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-15707");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1825243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1852009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1852014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1852022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1852030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1860978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1861118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1861581");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14309");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78, 122, 190, 416, 440, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fwupd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-aa64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-ia32-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-ia32-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-ppc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-ppc64le-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-tools-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shim-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shim-x64");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.0')) audit(AUDIT_OS_NOT, 'Red Hat 8.0', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel8/8.0/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.0/ppc64le/appstream/os',
      'content/e4s/rhel8/8.0/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.0/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.0/ppc64le/baseos/os',
      'content/e4s/rhel8/8.0/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.0/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.0/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.0/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.0/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.0/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.0/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.0/ppc64le/sap/debug',
      'content/e4s/rhel8/8.0/ppc64le/sap/os',
      'content/e4s/rhel8/8.0/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.0/x86_64/appstream/debug',
      'content/e4s/rhel8/8.0/x86_64/appstream/os',
      'content/e4s/rhel8/8.0/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.0/x86_64/baseos/debug',
      'content/e4s/rhel8/8.0/x86_64/baseos/os',
      'content/e4s/rhel8/8.0/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.0/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.0/x86_64/highavailability/os',
      'content/e4s/rhel8/8.0/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.0/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.0/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.0/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.0/x86_64/sap/debug',
      'content/e4s/rhel8/8.0/x86_64/sap/os',
      'content/e4s/rhel8/8.0/x86_64/sap/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'fwupd-1.1.4-2.el8_0', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fwupd-1.1.4-2.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'grub2-common-2.02-87.el8_0', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-efi-aa64-modules-2.02-87.el8_0', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-efi-ia32-2.02-87.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-efi-ia32-cdboot-2.02-87.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-efi-ia32-modules-2.02-87.el8_0', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-efi-x64-2.02-87.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-efi-x64-cdboot-2.02-87.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-efi-x64-modules-2.02-87.el8_0', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-pc-2.02-87.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-pc-modules-2.02-87.el8_0', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-ppc64le-2.02-87.el8_0', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-ppc64le-modules-2.02-87.el8_0', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-tools-2.02-87.el8_0', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-tools-2.02-87.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-tools-efi-2.02-87.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-tools-extra-2.02-87.el8_0', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-tools-extra-2.02-87.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-tools-minimal-2.02-87.el8_0', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'grub2-tools-minimal-2.02-87.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'shim-ia32-15-14.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'shim-x64-15-14.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Update Services for SAP Solutions repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fwupd / grub2-common / grub2-efi-aa64-modules / grub2-efi-ia32 / etc');
}
