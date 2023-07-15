##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0861. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(134668);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2019-0221",
    "CVE-2019-12418",
    "CVE-2019-17563",
    "CVE-2020-1938"
  );
  script_bugtraq_id(108545);
  script_xref(name:"RHSA", value:"2020:0861");
  script_xref(name:"IAVB", value:"2020-B-0010-S");
  script_xref(name:"IAVB", value:"2019-B-0048-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"IAVA", value:"2021-A-0196");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"RHEL 6 / 7 : Red Hat JBoss Web Server 3.1 Service Pack 8 (RHSA-2020:0861)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:0861 advisory.

  - tomcat: XSS in SSI printenv (CVE-2019-0221)

  - tomcat: local privilege escalation (CVE-2019-12418)

  - tomcat: Session fixation when using FORM authentication (CVE-2019-17563)

  - tomcat: Apache Tomcat AJP File Read/Inclusion Vulnerability (CVE-2020-1938)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-0221");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12418");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17563");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1938");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1713275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1785699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1785711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1806398");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(79, 284, 285, 384);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-jsp-2.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-servlet-3.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-webapps");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/jws/3/debug',
      'content/dist/rhel/server/6/6Server/i386/jws/3/os',
      'content/dist/rhel/server/6/6Server/i386/jws/3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jws/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jws/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/jws/3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'tomcat-native-1.2.23-21.redhat_21.ep7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat-native-1.2.23-21.redhat_21.ep7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-7.0.70-38.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-admin-webapps-7.0.70-38.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-docs-webapp-7.0.70-38.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-el-2.2-api-7.0.70-38.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-javadoc-7.0.70-38.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-jsp-2.2-api-7.0.70-38.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-jsvc-7.0.70-38.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-lib-7.0.70-38.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-log4j-7.0.70-38.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-selinux-7.0.70-38.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-servlet-3.0-api-7.0.70-38.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-webapps-7.0.70-38.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-8.0.36-42.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-admin-webapps-8.0.36-42.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-docs-webapp-8.0.36-42.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-el-2.2-api-8.0.36-42.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-javadoc-8.0.36-42.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-jsp-2.3-api-8.0.36-42.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-jsvc-8.0.36-42.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-lib-8.0.36-42.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-log4j-8.0.36-42.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-selinux-8.0.36-42.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-servlet-3.1-api-8.0.36-42.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-webapps-8.0.36-42.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jws/3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jws/3/os',
      'content/dist/rhel/server/7/7Server/x86_64/jws/3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'tomcat-native-1.2.23-21.redhat_21.ep7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-7.0.70-38.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-admin-webapps-7.0.70-38.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-docs-webapp-7.0.70-38.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-el-2.2-api-7.0.70-38.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-javadoc-7.0.70-38.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-jsp-2.2-api-7.0.70-38.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-jsvc-7.0.70-38.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-lib-7.0.70-38.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-log4j-7.0.70-38.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-selinux-7.0.70-38.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-servlet-3.0-api-7.0.70-38.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-webapps-7.0.70-38.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-8.0.36-42.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-admin-webapps-8.0.36-42.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-docs-webapp-8.0.36-42.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-el-2.2-api-8.0.36-42.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-javadoc-8.0.36-42.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-jsp-2.3-api-8.0.36-42.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-jsvc-8.0.36-42.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-lib-8.0.36-42.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-log4j-8.0.36-42.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-selinux-8.0.36-42.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-servlet-3.1-api-8.0.36-42.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-webapps-8.0.36-42.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tomcat-native / tomcat7 / tomcat7-admin-webapps / tomcat7-docs-webapp / etc');
}
