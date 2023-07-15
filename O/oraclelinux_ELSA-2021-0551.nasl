##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-0551.
##

include('compat.inc');

if (description)
{
  script_id(146637);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-7754",
    "CVE-2020-7774",
    "CVE-2020-7788",
    "CVE-2020-8265",
    "CVE-2020-8277",
    "CVE-2020-8287",
    "CVE-2020-15366"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Linux 8 : nodejs:14 (ELSA-2021-0551)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-0551 advisory.

  - This affects the package npm-user-validate before 1.0.1. The regex that validates user emails took
    exponentially longer to process long input strings beginning with @ characters. (CVE-2020-7754)

  - This affects the package ini before 1.3.6. If an attacker submits a malicious INI file to an application
    that parses it with ini.parse, they will pollute the prototype on the application. This can be exploited
    further depending on the context. (CVE-2020-7788)

  - Node.js versions before 10.23.1, 12.20.1, 14.15.4, 15.5.1 are vulnerable to a use-after-free bug in its
    TLS implementation. When writing to a TLS enabled socket, node::StreamBase::Write calls
    node::TLSWrap::DoWrite with a freshly allocated WriteWrap object as first argument. If the DoWrite method
    does not return an error, this object is passed back to the caller as part of a StreamWriteResult
    structure. This may be exploited to corrupt memory leading to a Denial of Service or potentially other
    exploits. (CVE-2020-8265)

  - Node.js versions before 10.23.1, 12.20.1, 14.15.4, 15.5.1 allow two copies of a header field in an HTTP
    request (for example, two Transfer-Encoding header fields). In this case, Node.js identifies the first
    header field and ignores the second. This can lead to HTTP Request Smuggling. (CVE-2020-8287)

  - A Node.js application that allows an attacker to trigger a DNS request for a host of their choice could
    trigger a Denial of Service in versions < 15.2.1, < 14.15.1, and < 12.19.1 by getting the application to
    resolve a DNS record with a larger number of responses. This is fixed in 15.2.1, 14.15.1, and 12.19.1.
    (CVE-2020-8277)

  - An issue was discovered in ajv.validate() in Ajv (aka Another JSON Schema Validator) 6.12.2. A carefully
    crafted JSON schema could be provided that allows execution of other code by prototype pollution. (While
    untrusted schemas are recommended against, the worst case of an untrusted schema should be a denial of
    service, not execution of code.) (CVE-2020-15366)

  - This affects the package y18n before 3.2.2, 4.0.1 and 5.0.5. PoC by po6ix: const y18n = require('y18n')();
    y18n.setLocale('__proto__'); y18n.updateLocale({polluted: true}); console.log(polluted); // true
    (CVE-2020-7774)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-0551.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7788");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-7774");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:npm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

module_ver = get_kb_item('Host/RedHat/appstream/nodejs');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:14');
if ('14' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module nodejs:' + module_ver);

appstreams = {
    'nodejs:14': [
      {'reference':'nodejs-14.15.4-2.module+el8.3.0+9657+a08a905a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-14.15.4-2.module+el8.3.0+9657+a08a905a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-14.15.4-2.module+el8.3.0+9657+a08a905a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-14.15.4-2.module+el8.3.0+9657+a08a905a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-docs-14.15.4-2.module+el8.3.0+9657+a08a905a', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-14.15.4-2.module+el8.3.0+9657+a08a905a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-14.15.4-2.module+el8.3.0+9657+a08a905a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-nodemon-2.0.3-1.module+el8.3.0+7818+6cd30d85', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nodejs-packaging-23-3.module+el8.3.0+7818+6cd30d85', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'npm-6.14.10-1.14.15.4.2.module+el8.3.0+9657+a08a905a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'npm-6.14.10-1.14.15.4.2.module+el8.3.0+9657+a08a905a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
};

flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  appstream = NULL;
  appstream_name = NULL;
  appstream_version = NULL;
  appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      reference = NULL;
      release = NULL;
      sp = NULL;
      cpu = NULL;
      el_string = NULL;
      rpm_spec_vers_cmp = NULL;
      epoch = NULL;
      allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:14');

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-devel / nodejs-docs / etc');
}
