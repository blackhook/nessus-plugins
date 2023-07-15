#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:1276. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159603);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2020-28851",
    "CVE-2020-28852",
    "CVE-2021-3121",
    "CVE-2021-3749",
    "CVE-2021-29482",
    "CVE-2021-29923",
    "CVE-2021-36221",
    "CVE-2021-43565",
    "CVE-2021-43824",
    "CVE-2021-43825",
    "CVE-2021-43826",
    "CVE-2022-21654",
    "CVE-2022-21655",
    "CVE-2022-23606",
    "CVE-2022-23635",
    "CVE-2022-24726"
  );
  script_xref(name:"RHSA", value:"2022:1276");
  script_xref(name:"IAVB", value:"2020-B-0071-S");
  script_xref(name:"IAVB", value:"2021-B-0047-S");

  script_name(english:"RHEL 8 : Red Hat OpenShift Service Mesh 2.0.9 (RHSA-2022:1276)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:1276 advisory.

  - golang.org/x/text: Panic in language.ParseAcceptLanguage while parsing -u- extension (CVE-2020-28851)

  - golang.org/x/text: Panic in language.ParseAcceptLanguage while processing bcp47 tag (CVE-2020-28852)

  - ulikunitz/xz: Infinite loop in readUvarint allows for denial of service (CVE-2021-29482)

  - golang: net: incorrect parsing of extraneous zero characters at the beginning of an IP address octet
    (CVE-2021-29923)

  - gogo/protobuf: plugin/unmarshal/unmarshal.go lacks certain index validation (CVE-2021-3121)

  - golang: net/http/httputil: panic due to racy read of persistConn after handler panic (CVE-2021-36221)

  - nodejs-axios: Regular expression denial of service in trim function (CVE-2021-3749)

  - golang.org/x/crypto: empty plaintext packet causes panic (CVE-2021-43565)

  - envoy: Null pointer dereference when using JWT filter safe_regex match (CVE-2021-43824)

  - envoy: Use-after-free when response filters increase response data (CVE-2021-43825)

  - envoy: Use-after-free when tunneling TCP over HTTP (CVE-2021-43826)

  - envoy: Incorrect configuration handling allows mTLS session re-use without re-validation (CVE-2022-21654)

  - envoy: Incorrect handling of internal redirects to routes with a direct response entry (CVE-2022-21655)

  - envoy: Stack exhaustion when a cluster is deleted via Cluster Discovery Service (CVE-2022-23606)

  - istio: unauthenticated control plane denial of service attack (CVE-2022-23635)

  - istio: Unauthenticated control plane denial of service attack due to stack exhaustion (CVE-2022-24726)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-28851");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-28852");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3121");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3749");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-29482");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-29923");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-36221");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-43565");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-43824");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-43825");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-43826");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21654");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21655");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23606");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23635");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24726");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1913333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1913338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1921650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1954368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1995656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1999784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2030787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2050758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2057277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2061638");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3121");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21654");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 129, 200, 287, 362, 367, 400, 416, 476, 670, 770, 835);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kiali");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-istioctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-mixc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-mixs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-pilot-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-pilot-discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-proxy");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
      'content/dist/layered/rhel8/s390x/ossm/2.0/debug',
      'content/dist/layered/rhel8/s390x/ossm/2.0/os',
      'content/dist/layered/rhel8/s390x/ossm/2.0/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ossm/2.0/debug',
      'content/dist/layered/rhel8/x86_64/ossm/2.0/os',
      'content/dist/layered/rhel8/x86_64/ossm/2.0/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kiali-v1.24.7.redhat1-1.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'kiali-v1.24.7.redhat1-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-2.0.9-3.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-2.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-istioctl-2.0.9-3.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-istioctl-2.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-mixc-2.0.9-3.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-mixc-2.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-mixs-2.0.9-3.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-mixs-2.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-pilot-agent-2.0.9-3.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-pilot-agent-2.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-pilot-discovery-2.0.9-3.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-pilot-discovery-2.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-prometheus-2.14.0-16.el8.1', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-prometheus-2.14.0-16.el8.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-proxy-2.0.9-3.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'},
      {'reference':'servicemesh-proxy-2.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'servicemesh'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kiali / servicemesh / servicemesh-istioctl / servicemesh-mixc / etc');
}
