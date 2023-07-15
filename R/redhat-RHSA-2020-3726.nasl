##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3726. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(140523);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2020-9490");
  script_xref(name:"RHSA", value:"2020:3726");

  script_name(english:"RHEL 8 : httpd:2.4 (RHSA-2020:3726)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:3726 advisory.

  - httpd: Push diary crash on specifically crafted HTTP/2 header (CVE-2020-9490)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9490");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1866560");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9490");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.1')) audit(AUDIT_OS_NOT, 'Red Hat 8.1', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'httpd:2.4': [
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
        'content/e4s/rhel8/8.1/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.1/aarch64/appstream/debug',
        'content/eus/rhel8/8.1/aarch64/appstream/os',
        'content/eus/rhel8/8.1/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.1/aarch64/baseos/debug',
        'content/eus/rhel8/8.1/aarch64/baseos/os',
        'content/eus/rhel8/8.1/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.1/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.1/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.1/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.1/aarch64/highavailability/debug',
        'content/eus/rhel8/8.1/aarch64/highavailability/os',
        'content/eus/rhel8/8.1/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.1/aarch64/supplementary/debug',
        'content/eus/rhel8/8.1/aarch64/supplementary/os',
        'content/eus/rhel8/8.1/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/appstream/debug',
        'content/eus/rhel8/8.1/ppc64le/appstream/os',
        'content/eus/rhel8/8.1/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/baseos/debug',
        'content/eus/rhel8/8.1/ppc64le/baseos/os',
        'content/eus/rhel8/8.1/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.1/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.1/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.1/ppc64le/highavailability/os',
        'content/eus/rhel8/8.1/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.1/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.1/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.1/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.1/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/sap/debug',
        'content/eus/rhel8/8.1/ppc64le/sap/os',
        'content/eus/rhel8/8.1/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.1/ppc64le/supplementary/os',
        'content/eus/rhel8/8.1/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/appstream/debug',
        'content/eus/rhel8/8.1/s390x/appstream/os',
        'content/eus/rhel8/8.1/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/baseos/debug',
        'content/eus/rhel8/8.1/s390x/baseos/os',
        'content/eus/rhel8/8.1/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.1/s390x/codeready-builder/os',
        'content/eus/rhel8/8.1/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/highavailability/debug',
        'content/eus/rhel8/8.1/s390x/highavailability/os',
        'content/eus/rhel8/8.1/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.1/s390x/resilientstorage/os',
        'content/eus/rhel8/8.1/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/sap/debug',
        'content/eus/rhel8/8.1/s390x/sap/os',
        'content/eus/rhel8/8.1/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/supplementary/debug',
        'content/eus/rhel8/8.1/s390x/supplementary/os',
        'content/eus/rhel8/8.1/s390x/supplementary/source/SRPMS',
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
        {'reference':'httpd-2.4.37-16.module+el8.1.0+4134+e6bad0ed', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpd-devel-2.4.37-16.module+el8.1.0+4134+e6bad0ed', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpd-filesystem-2.4.37-16.module+el8.1.0+4134+e6bad0ed', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpd-manual-2.4.37-16.module+el8.1.0+4134+e6bad0ed', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpd-tools-2.4.37-16.module+el8.1.0+4134+e6bad0ed', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mod_http2-1.11.3-3.module+el8.1.0+7763+babdfe5b.1', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mod_ldap-2.4.37-16.module+el8.1.0+4134+e6bad0ed', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mod_md-2.4.37-16.module+el8.1.0+4134+e6bad0ed', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mod_proxy_html-2.4.37-16.module+el8.1.0+4134+e6bad0ed', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'mod_session-2.4.37-16.module+el8.1.0+4134+e6bad0ed', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mod_ssl-2.4.37-16.module+el8.1.0+4134+e6bad0ed', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/httpd');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module httpd:2.4');
if ('2.4' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module httpd:' + module_ver);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module httpd:2.4');

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support or Update Services for SAP Solutions repositories.\n' +
    'Access to these repositories requires a paid RHEL subscription.\n';
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd / httpd-devel / httpd-filesystem / httpd-manual / httpd-tools / etc');
}
