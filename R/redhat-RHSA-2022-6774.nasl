#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:6774. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165646);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2022-41318");
  script_xref(name:"RHSA", value:"2022:6774");

  script_name(english:"RHEL 8 : squid:4 (RHSA-2022:6774)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2022:6774 advisory.

  - squid: buffer-over-read in SSPI and SMB authentication (CVE-2022-41318)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-41318");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:6774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2129771");
  script_set_attribute(attribute:"solution", value:
"Update the affected libecap, libecap-devel and / or squid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41318");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(126);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libecap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libecap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.1')) audit(AUDIT_OS_NOT, 'Red Hat 8.1', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'squid:4': [
    {
      'repo_relative_urls': [
        'content/e4s/rhel8/8.1/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.1/ppc64le/appstream/os',
        'content/e4s/rhel8/8.1/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.1/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.1/ppc64le/baseos/os',
        'content/e4s/rhel8/8.1/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.1/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.1/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.1/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.1/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.1/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.1/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.1/ppc64le/sap/debug',
        'content/e4s/rhel8/8.1/ppc64le/sap/os',
        'content/e4s/rhel8/8.1/ppc64le/sap/source/SRPMS',
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
        'content/e4s/rhel8/8.1/x86_64/sap/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'libecap-1.0.1-2.module+el8.1.0+4044+36416a77', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libecap-1.0.1-2.module+el8.1.0+4044+36416a77', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libecap-devel-1.0.1-2.module+el8.1.0+4044+36416a77', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libecap-devel-1.0.1-2.module+el8.1.0+4044+36416a77', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'squid-4.4-8.module+el8.1.0+16758+65e5269e.5', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
        {'reference':'squid-4.4-8.module+el8.1.0+16758+65e5269e.5', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/squid');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module squid:4');
if ('4' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module squid:' + module_ver);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module squid:4');

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
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libecap / libecap-devel / squid');
}
