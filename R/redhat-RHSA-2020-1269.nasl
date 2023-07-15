##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1269. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(135091);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2019-10195", "CVE-2019-14867");
  script_xref(name:"RHSA", value:"2020:1269");

  script_name(english:"RHEL 8 : idm:DL1 (RHSA-2020:1269)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1269 advisory.

  - ipa: Batch API logging user passwords to /var/log/httpd/error_log (CVE-2019-10195)

  - ipa: Denial of service in IPA server due to wrong use of ber_scanf() (CVE-2019-14867)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10195");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14867");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1726223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1766920");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14867");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 200, 400, 532);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-dyndb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-idoverride-memberof-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:opendnssec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ipaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-jwcrypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-kdcproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pyusb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-qrcode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-qrcode-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-yubico");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slapi-nis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:softhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:softhsm-devel");
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
  'idm:DL1': [
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
        {'reference':'bind-dyndb-ldap-11.1-13.module+el8+2555+b334d87b', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'bind-dyndb-ldap-11.1-13.module+el8+2555+b334d87b', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'custodia-0.6.0-2.module+el8+2555+b334d87b', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-client-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-client-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-client-common-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-common-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-idoverride-memberof-plugin-0.0.4-6.module+el8+2555+b334d87b', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-idoverride-memberof-plugin-0.0.4-6.module+el8+2555+b334d87b', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-python-compat-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-server-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-server-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-server-common-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-server-dns-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-server-trust-ad-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ipa-server-trust-ad-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'opendnssec-1.4.14-1.module+el8+2555+b334d87b', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'opendnssec-1.4.14-1.module+el8+2555+b334d87b', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-custodia-0.6.0-2.module+el8+2555+b334d87b', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-ipaclient-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-ipalib-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-ipaserver-4.7.1-12.module+el8.0.0+5776+863ecd37', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-jwcrypto-0.5.0-1.module+el8+2555+b334d87b', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-kdcproxy-0.4-3.module+el8+2555+b334d87b', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-pyusb-1.0.0-9.module+el8+2555+b334d87b', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-qrcode-5.1-11.module+el8+2555+b334d87b', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-qrcode-core-5.1-11.module+el8+2555+b334d87b', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-yubico-1.3.2-9.module+el8+2555+b334d87b', 'sp':'0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slapi-nis-0.56.2-7.module+el8+2555+b334d87b', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slapi-nis-0.56.2-7.module+el8+2555+b334d87b', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'softhsm-2.4.0-2.module+el8+2555+b334d87b', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'softhsm-2.4.0-2.module+el8+2555+b334d87b', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'softhsm-devel-2.4.0-2.module+el8+2555+b334d87b', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'softhsm-devel-2.4.0-2.module+el8+2555+b334d87b', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/idm');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module idm:DL1');
if ('DL1' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module idm:' + module_ver);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module idm:DL1');

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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind-dyndb-ldap / custodia / ipa-client / ipa-client-common / etc');
}
