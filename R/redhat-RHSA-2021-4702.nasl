#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:4702. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155377);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2019-14853",
    "CVE-2019-14859",
    "CVE-2019-25025",
    "CVE-2020-8130",
    "CVE-2020-8908",
    "CVE-2020-14343",
    "CVE-2020-26247",
    "CVE-2021-3413",
    "CVE-2021-3494",
    "CVE-2021-20256",
    "CVE-2021-21330",
    "CVE-2021-22885",
    "CVE-2021-22902",
    "CVE-2021-22904",
    "CVE-2021-28658",
    "CVE-2021-29509",
    "CVE-2021-31542",
    "CVE-2021-32740",
    "CVE-2021-33203",
    "CVE-2021-33503",
    "CVE-2021-33571"
  );
  script_xref(name:"RHSA", value:"2021:4702");
  script_xref(name:"IAVA", value:"2021-A-0463");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : Satellite 6.10 Release (Moderate) (RHSA-2021:4702)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:4702 advisory.

  - python-ecdsa: Unexpected and  undocumented exceptions during signature decoding (CVE-2019-14853)

  - python-ecdsa: DER encoding is not being verified in signatures (CVE-2019-14859)

  - rubygem-activerecord-session_store: hijack sessions by using timing attacks targeting the session id
    (CVE-2019-25025)

  - PyYAML: incomplete fix for CVE-2020-1747 (CVE-2020-14343)

  - rubygem-nokogiri: XML external entity injection via Nokogiri::XML::Schema (CVE-2020-26247)

  - rake: OS Command Injection via egrep in Rake::FileList (CVE-2020-8130)

  - guava: local information disclosure via temporary directory created with unsafe permissions
    (CVE-2020-8908)

  - Satellite: BMC controller credential leak via API (CVE-2021-20256)

  - python-aiohttp: Open redirect in aiohttp.web_middlewares.normalize_path_middleware (CVE-2021-21330)

  - rubygem-actionpack: Possible Information Disclosure / Unintended Method Execution in Action Pack
    (CVE-2021-22885)

  - rails: Possible Denial of Service vulnerability in Action Dispatch (CVE-2021-22902)

  - rails: Possible DoS Vulnerability in Action Controller Token Authentication (CVE-2021-22904)

  - django: potential directory-traversal via uploaded files (CVE-2021-28658)

  - rubygem-puma: incomplete fix for CVE-2019-16770 allows Denial of Service (DoS) (CVE-2021-29509)

  - django: Potential directory-traversal via uploaded files (CVE-2021-31542)

  - rubygem-addressable: ReDoS in templates (CVE-2021-32740)

  - django: Potential directory traversal via ``admindocs`` (CVE-2021-33203)

  - python-urllib3: ReDoS in the parsing of authority part of URL (CVE-2021-33503)

  - django: Possible indeterminate SSRF, RFI, and LFI attacks since validators accepted leading zeros in IPv4
    addresses (CVE-2021-33571)

  - Satellite: Azure compute resource secret_key leak to authenticated users (CVE-2021-3413)

  - foreman: possible man-in-the-middle in smart_proxy realm_freeipa (CVE-2021-3494)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14853");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14859");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-25025");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8130");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8908");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14343");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26247");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3413");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3494");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-20256");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21330");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22885");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22902");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22904");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-28658");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-29509");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-31542");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-32740");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33203");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33503");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33571");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:4702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1758704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1860466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1906919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1912487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930352");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1933364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1935724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1944801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1948005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1954294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1957441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1961379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1961382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1964874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1966251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1966253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1968074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1979702");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14343");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 22, 78, 200, 276, 319, 347, 391, 400, 601, 611, 835, 918);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ecdsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-capsule");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-activerecord-session_store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-addressable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-puma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rails");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/server/7/7Server/x86_64/sat-capsule/6.10/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sat-capsule/6.10/os',
      'content/dist/rhel/server/7/7Server/x86_64/sat-capsule/6.10/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/satellite/6.10/debug',
      'content/dist/rhel/server/7/7Server/x86_64/satellite/6.10/os',
      'content/dist/rhel/server/7/7Server/x86_64/satellite/6.10/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'candlepin-4.0.9-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-2.5.2.17-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-django-2.2.24-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-ecdsa-0.13.3-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pyyaml-5.4.1-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-urllib3-1.26.5-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'satellite-6.10.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'satellite-capsule-6.10.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-actionpack-6.0.3.7-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-activerecord-session_store-2.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-addressable-2.8.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-nokogiri-1.11.3-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-puma-5.3.2-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rails-6.0.3.7-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'candlepin / foreman / python3-django / python3-ecdsa / python3-pyyaml / etc');
}
