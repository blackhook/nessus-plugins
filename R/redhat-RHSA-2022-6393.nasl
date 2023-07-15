#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:6393. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164843);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/02");

  script_cve_id(
    "CVE-2020-11022",
    "CVE-2020-11023",
    "CVE-2021-22096",
    "CVE-2021-23358",
    "CVE-2022-2806",
    "CVE-2022-31129"
  );
  script_xref(name:"RHSA", value:"2022:6393");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 8 : RHV Manager (ovirt-engine) [ovirt-4.5.2] bug fix and (RHSA-2022:6393)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:6393 advisory.

  - jquery: Cross-site scripting due to improper injQuery.htmlPrefilter method (CVE-2020-11022)

  - jquery: Untrusted code execution via <option> tag in HTML passed to DOM manipulation methods
    (CVE-2020-11023)

  - springframework: malicious input leads to insertion of additional log entries (CVE-2021-22096)

  - nodejs-underscore: Arbitrary code execution via the template function (CVE-2021-23358)

  - ovirt-log-collector: RHVM admin password is logged unfiltered (CVE-2022-2806)

  - moment: inefficient parsing algorithm resulting in DoS (CVE-2022-31129)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11022");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11023");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22096");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-23358");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-2806");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-31129");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:6393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1828406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1850004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1944286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2034584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2080005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2105075");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23358");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 94, 200, 400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-health-check-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-cinderlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-imageio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-ovirt-engine-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-tools-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-ui-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-log-collector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-web-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ovirt-engine-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhvm");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/rhv-manager/4.4/debug',
      'content/dist/layered/rhel8/x86_64/rhv-manager/4.4/os',
      'content/dist/layered/rhel8/x86_64/rhv-manager/4.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ovirt-engine-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-backend-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-dbscripts-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-health-check-bundler-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-restapi-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-base-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-plugin-cinderlib-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-plugin-imageio-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-plugin-ovirt-engine-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-plugin-ovirt-engine-common-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-plugin-vmconsole-proxy-helper-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-plugin-websocket-proxy-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-tools-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-tools-backup-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-ui-extensions-1.3.5-1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-vmconsole-proxy-helper-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-webadmin-portal-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-websocket-proxy-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-log-collector-4.4.7-2.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-web-ui-1.9.1-1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'python3-ovirt-engine-lib-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'rhvm-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'}
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ovirt-engine / ovirt-engine-backend / ovirt-engine-dbscripts / etc');
}
