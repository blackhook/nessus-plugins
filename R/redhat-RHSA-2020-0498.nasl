##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0498. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(133746);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2019-19336");
  script_xref(name:"RHSA", value:"2020:0498");

  script_name(english:"RHEL 7 : Red Hat Virtualization Engine (RHSA-2020:0498)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:0498 advisory.

  - ovirt-engine: response_type parameter allows reflected XSS (CVE-2019-19336)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19336");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1781001");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19336");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-dwh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-dwh-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-extensions-api-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-extensions-api-impl-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-health-check-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-metrics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-cinderlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-ovirt-engine-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-tools-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-fast-forward-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-imageio-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-imageio-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-imageio-proxy-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-web-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-ovirt-engine-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhv-log-collector-analyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:v2v-conversion-host-ansible");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7.3/x86_64/rhev-mgmt-agent/3/debug',
      'content/dist/rhel/server/7/7.3/x86_64/rhev-mgmt-agent/3/os',
      'content/dist/rhel/server/7/7.3/x86_64/rhev-mgmt-agent/3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhev-mgmt-agent/3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhev-mgmt-agent/3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhev-mgmt-agent/3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhevh/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhevh/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhevh/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager-tools/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager-tools/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager-tools/4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager/4.0/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager/4.0/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager/4.0/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager/4.1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager/4.1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager/4.1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager/4.2/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager/4.2/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager/4.2/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager/4.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager/4.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager/4.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-mgmt-agent/4.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-mgmt-agent/4.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-mgmt-agent/4.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-mgmt-agent/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-mgmt-agent/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-mgmt-agent/4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-power/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-power/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-power/4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-tools/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-tools/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-tools/4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv/4.0/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv/4.0/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv/4.0/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv/4.1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv/4.1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv/4.1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh-build/4.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh-build/4.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh-build/4.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh-build/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh-build/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh-build/4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ovirt-engine-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-backend-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-dbscripts-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-dwh-4.3.8-1.el7ev', 'release':'7', 'el_string':'el7ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-dwh-setup-4.3.8-1.el7ev', 'release':'7', 'el_string':'el7ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-extensions-api-impl-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-extensions-api-impl-javadoc-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-health-check-bundler-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-metrics-1.3.6.2-1.el7ev', 'release':'7', 'el_string':'el7ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-restapi-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-base-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-plugin-cinderlib-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-plugin-ovirt-engine-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-plugin-ovirt-engine-common-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-plugin-vmconsole-proxy-helper-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-setup-plugin-websocket-proxy-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-tools-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-tools-backup-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-vmconsole-proxy-helper-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-webadmin-portal-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-engine-websocket-proxy-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-fast-forward-upgrade-1.0.0-16.el7ev', 'release':'7', 'el_string':'el7ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-imageio-common-1.5.3-0.el7ev', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-imageio-proxy-1.5.3-0.el7ev', 'release':'7', 'el_string':'el7ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-imageio-proxy-setup-1.5.3-0.el7ev', 'release':'7', 'el_string':'el7ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-web-ui-1.6.0-2.el7ev', 'release':'7', 'el_string':'el7ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'python2-ovirt-engine-lib-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'rhv-log-collector-analyzer-0.2.15-0.el7ev', 'release':'7', 'el_string':'el7ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'rhvm-4.3.8.2-0.4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'v2v-conversion-host-ansible-1.16.0-3.el7ev', 'release':'7', 'el_string':'el7ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'}
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
