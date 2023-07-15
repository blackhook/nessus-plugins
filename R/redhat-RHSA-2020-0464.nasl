##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0464. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(133633);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2019-14824");
  script_xref(name:"RHSA", value:"2020:0464");

  script_name(english:"RHEL 8 : 389-ds:1.4 (RHSA-2020:0464)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:0464 advisory.

  - 389-ds-base: Read permission check bypass via the deref plugin (CVE-2019-14824)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14824");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1747448");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14824");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(416, 732);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base-legacy-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-lib389");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var appstreams = {
  '389-ds:1.4': [
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
        {'reference':'389-ds-base-1.4.0.20-10.1.module+el8.0.0+4597+364a3066', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'389-ds-base-1.4.0.20-10.1.module+el8.0.0+4597+364a3066', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'389-ds-base-devel-1.4.0.20-10.1.module+el8.0.0+4597+364a3066', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'389-ds-base-devel-1.4.0.20-10.1.module+el8.0.0+4597+364a3066', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'389-ds-base-legacy-tools-1.4.0.20-10.1.module+el8.0.0+4597+364a3066', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'389-ds-base-legacy-tools-1.4.0.20-10.1.module+el8.0.0+4597+364a3066', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'389-ds-base-libs-1.4.0.20-10.1.module+el8.0.0+4597+364a3066', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'389-ds-base-libs-1.4.0.20-10.1.module+el8.0.0+4597+364a3066', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'389-ds-base-snmp-1.4.0.20-10.1.module+el8.0.0+4597+364a3066', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'389-ds-base-snmp-1.4.0.20-10.1.module+el8.0.0+4597+364a3066', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-lib389-1.4.0.20-10.1.module+el8.0.0+4597+364a3066', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/389-ds');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module 389-ds:1.4');
if ('1.4' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module 389-ds:' + module_ver);

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      foreach var package_array ( module_array['pkgs'] ) {
        var reference = NULL;
        var _release = NULL;
        var sp = NULL;
        var _cpu = NULL;
        var el_string = NULL;
        var rpm_spec_vers_cmp = NULL;
        var epoch = NULL;
        var allowmaj = NULL;
        var exists_check = NULL;
        if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module 389-ds:1.4');

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Update Services for SAP Solutions repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, '389-ds-base / 389-ds-base-devel / 389-ds-base-legacy-tools / etc');
}
