##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3475. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(139669);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2020-8616", "CVE-2020-8617");
  script_xref(name:"RHSA", value:"2020:3475");
  script_xref(name:"IAVA", value:"2020-A-0217-S");

  script_name(english:"RHEL 7 : bind (RHSA-2020:3475)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:3475 advisory.

  - bind: BIND does not sufficiently limit the number of fetches performed when processing referrals
    (CVE-2020-8616)

  - bind: A logic error in code which checks TSIG validity can be used to trigger an assertion failure in
    tsig.c (CVE-2020-8617)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8616");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8617");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1836118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1836124");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8617");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8616");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(400, 617);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:7.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '7.6')) audit(AUDIT_OS_NOT, 'Red Hat 7.6', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/7/7.6/x86_64/debug',
      'content/aus/rhel/server/7/7.6/x86_64/optional/debug',
      'content/aus/rhel/server/7/7.6/x86_64/optional/os',
      'content/aus/rhel/server/7/7.6/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/7/7.6/x86_64/os',
      'content/aus/rhel/server/7/7.6/x86_64/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/debug',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/highavailability/debug',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/highavailability/os',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/optional/debug',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/optional/os',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/optional/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/os',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/sap-hana/debug',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/sap-hana/os',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/sap-hana/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/sap/debug',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/sap/os',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/source/SRPMS',
      'content/e4s/rhel/server/7/7.6/x86_64/debug',
      'content/e4s/rhel/server/7/7.6/x86_64/highavailability/debug',
      'content/e4s/rhel/server/7/7.6/x86_64/highavailability/os',
      'content/e4s/rhel/server/7/7.6/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel/server/7/7.6/x86_64/optional/debug',
      'content/e4s/rhel/server/7/7.6/x86_64/optional/os',
      'content/e4s/rhel/server/7/7.6/x86_64/optional/source/SRPMS',
      'content/e4s/rhel/server/7/7.6/x86_64/os',
      'content/e4s/rhel/server/7/7.6/x86_64/sap-hana/debug',
      'content/e4s/rhel/server/7/7.6/x86_64/sap-hana/os',
      'content/e4s/rhel/server/7/7.6/x86_64/sap-hana/source/SRPMS',
      'content/e4s/rhel/server/7/7.6/x86_64/sap/debug',
      'content/e4s/rhel/server/7/7.6/x86_64/sap/os',
      'content/e4s/rhel/server/7/7.6/x86_64/sap/source/SRPMS',
      'content/e4s/rhel/server/7/7.6/x86_64/source/SRPMS',
      'content/eus/rhel/computenode/7/7.6/x86_64/debug',
      'content/eus/rhel/computenode/7/7.6/x86_64/optional/debug',
      'content/eus/rhel/computenode/7/7.6/x86_64/optional/os',
      'content/eus/rhel/computenode/7/7.6/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/7/7.6/x86_64/os',
      'content/eus/rhel/computenode/7/7.6/x86_64/source/SRPMS',
      'content/eus/rhel/power-le/7/7.6/ppc64le/debug',
      'content/eus/rhel/power-le/7/7.6/ppc64le/highavailability/debug',
      'content/eus/rhel/power-le/7/7.6/ppc64le/highavailability/os',
      'content/eus/rhel/power-le/7/7.6/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel/power-le/7/7.6/ppc64le/optional/debug',
      'content/eus/rhel/power-le/7/7.6/ppc64le/optional/os',
      'content/eus/rhel/power-le/7/7.6/ppc64le/optional/source/SRPMS',
      'content/eus/rhel/power-le/7/7.6/ppc64le/os',
      'content/eus/rhel/power-le/7/7.6/ppc64le/resilientstorage/debug',
      'content/eus/rhel/power-le/7/7.6/ppc64le/resilientstorage/os',
      'content/eus/rhel/power-le/7/7.6/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel/power-le/7/7.6/ppc64le/sap-hana/debug',
      'content/eus/rhel/power-le/7/7.6/ppc64le/sap-hana/os',
      'content/eus/rhel/power-le/7/7.6/ppc64le/sap-hana/source/SRPMS',
      'content/eus/rhel/power-le/7/7.6/ppc64le/sap/debug',
      'content/eus/rhel/power-le/7/7.6/ppc64le/sap/os',
      'content/eus/rhel/power-le/7/7.6/ppc64le/sap/source/SRPMS',
      'content/eus/rhel/power-le/7/7.6/ppc64le/source/SRPMS',
      'content/eus/rhel/power/7/7.6/ppc64/debug',
      'content/eus/rhel/power/7/7.6/ppc64/optional/debug',
      'content/eus/rhel/power/7/7.6/ppc64/optional/os',
      'content/eus/rhel/power/7/7.6/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/7/7.6/ppc64/os',
      'content/eus/rhel/power/7/7.6/ppc64/sap/debug',
      'content/eus/rhel/power/7/7.6/ppc64/sap/os',
      'content/eus/rhel/power/7/7.6/ppc64/sap/source/SRPMS',
      'content/eus/rhel/power/7/7.6/ppc64/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/debug',
      'content/eus/rhel/server/7/7.6/x86_64/highavailability/debug',
      'content/eus/rhel/server/7/7.6/x86_64/highavailability/os',
      'content/eus/rhel/server/7/7.6/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/optional/debug',
      'content/eus/rhel/server/7/7.6/x86_64/optional/os',
      'content/eus/rhel/server/7/7.6/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/os',
      'content/eus/rhel/server/7/7.6/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/7/7.6/x86_64/resilientstorage/os',
      'content/eus/rhel/server/7/7.6/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/sap-hana/debug',
      'content/eus/rhel/server/7/7.6/x86_64/sap-hana/os',
      'content/eus/rhel/server/7/7.6/x86_64/sap-hana/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/sap/debug',
      'content/eus/rhel/server/7/7.6/x86_64/sap/os',
      'content/eus/rhel/server/7/7.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/7/7.6/s390x/debug',
      'content/eus/rhel/system-z/7/7.6/s390x/optional/debug',
      'content/eus/rhel/system-z/7/7.6/s390x/optional/os',
      'content/eus/rhel/system-z/7/7.6/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/7/7.6/s390x/os',
      'content/eus/rhel/system-z/7/7.6/s390x/sap/debug',
      'content/eus/rhel/system-z/7/7.6/s390x/sap/os',
      'content/eus/rhel/system-z/7/7.6/s390x/sap/source/SRPMS',
      'content/eus/rhel/system-z/7/7.6/s390x/source/SRPMS',
      'content/tus/rhel/server/7/7.6/x86_64/debug',
      'content/tus/rhel/server/7/7.6/x86_64/highavailability/debug',
      'content/tus/rhel/server/7/7.6/x86_64/highavailability/os',
      'content/tus/rhel/server/7/7.6/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel/server/7/7.6/x86_64/optional/debug',
      'content/tus/rhel/server/7/7.6/x86_64/optional/os',
      'content/tus/rhel/server/7/7.6/x86_64/optional/source/SRPMS',
      'content/tus/rhel/server/7/7.6/x86_64/os',
      'content/tus/rhel/server/7/7.6/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bind-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.9.4-74.el7_6.4', 'sp':'6', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.9.4-74.el7_6.4', 'sp':'6', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-lite-9.9.4-74.el7_6.4', 'sp':'6', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-license-9.9.4-74.el7_6.4', 'sp':'6', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-lite-devel-9.9.4-74.el7_6.4', 'sp':'6', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-pkcs11-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-pkcs11-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-pkcs11-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-pkcs11-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-pkcs11-devel-9.9.4-74.el7_6.4', 'sp':'6', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-pkcs11-libs-9.9.4-74.el7_6.4', 'sp':'6', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-pkcs11-utils-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-pkcs11-utils-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-pkcs11-utils-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-pkcs11-utils-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-chroot-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-chroot-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-chroot-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-chroot-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.9.4-74.el7_6.4', 'sp':'6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
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
    'Advanced Update Support, Extended Update Support, Telco Extended Update Support or Update Services for SAP Solutions repositories.\n' +
    'Access to these repositories requires a paid RHEL subscription.\n';
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-chroot / bind-devel / bind-libs / bind-libs-lite / etc');
}
