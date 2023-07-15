##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:4743. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145969);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2019-12520",
    "CVE-2019-12521",
    "CVE-2019-12523",
    "CVE-2019-12524",
    "CVE-2019-12526",
    "CVE-2019-12528",
    "CVE-2019-12529",
    "CVE-2019-12854",
    "CVE-2019-18676",
    "CVE-2019-18677",
    "CVE-2019-18678",
    "CVE-2019-18679",
    "CVE-2019-18860",
    "CVE-2020-8449",
    "CVE-2020-8450",
    "CVE-2020-14058",
    "CVE-2020-15049",
    "CVE-2020-24606"
  );
  script_xref(name:"RHSA", value:"2020:4743");

  script_name(english:"CentOS 8 : squid:4 (CESA-2020:4743)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:4743 advisory.

  - squid: Improper input validation in request allows for proxy manipulation (CVE-2019-12520)

  - squid: Off-by-one error in addStackElement allows for heap buffer overflow and crash (CVE-2019-12521)

  - squid: Improper input validation in URI processor (CVE-2019-12523)

  - squid: Improper access restriction in url_regex may lead to security bypass (CVE-2019-12524)

  - squid: Heap overflow issue in URN processing (CVE-2019-12526)

  - squid: Information Disclosure issue in FTP Gateway (CVE-2019-12528)

  - squid: Out of bounds read in Proxy-Authorization header causes DoS (CVE-2019-12529)

  - squid: Denial of service in cachemgr.cgi (CVE-2019-12854)

  - squid: Buffer overflow in URI processor (CVE-2019-18676)

  - squid: Cross-Site Request Forgery issue in HTTP Request processing (CVE-2019-18677)

  - squid: HTTP Request Splitting issue in HTTP message processing (CVE-2019-18678)

  - squid: Information Disclosure issue in HTTP Digest Authentication (CVE-2019-18679)

  - squid: Mishandled HTML in the host parameter to cachemgr.cgi results in insecure behaviour
    (CVE-2019-18860)

  - squid: DoS in TLS handshake (CVE-2020-14058)

  - squid: Request smuggling and poisoning attack against the HTTP cache (CVE-2020-15049)

  - squid: Improper input validation could result in a DoS (CVE-2020-24606)

  - squid: Improper input validation issues in HTTP Request processing (CVE-2020-8449)

  - squid: Buffer overflow in reverse-proxy configurations (CVE-2020-8450)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4743");
  script_set_attribute(attribute:"solution", value:
"Update the affected libecap, libecap-devel and / or squid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8450");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-12526");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libecap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libecap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< os_release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/squid');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module squid:4');
if ('4' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module squid:' + module_ver);

var appstreams = {
    'squid:4': [
      {'reference':'libecap-1.0.1-2.module_el8.1.0+197+0c39cdc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libecap-1.0.1-2.module_el8.1.0+197+0c39cdc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libecap-devel-1.0.1-2.module_el8.1.0+197+0c39cdc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libecap-devel-1.0.1-2.module_el8.1.0+197+0c39cdc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'squid-4.11-3.module_el8.3.0+558+7bf80f5f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'squid-4.11-3.module_el8.3.0+558+7bf80f5f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
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
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module squid:4');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libecap / libecap-devel / squid');
}
