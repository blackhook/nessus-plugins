#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-5171.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156123);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/04");

  script_cve_id(
    "CVE-2020-7788",
    "CVE-2020-28469",
    "CVE-2021-3807",
    "CVE-2021-3918",
    "CVE-2021-22959",
    "CVE-2021-22960",
    "CVE-2021-33502"
  );
  script_xref(name:"IAVB", value:"2021-B-0059-S");

  script_name(english:"Oracle Linux 8 : nodejs:16 (ELSA-2021-5171)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-5171 advisory.

  - This affects the package ini before 1.3.6. If an attacker submits a malicious INI file to an application
    that parses it with ini.parse, they will pollute the prototype on the application. This can be exploited
    further depending on the context. (CVE-2020-7788)

  - This affects the package glob-parent before 5.1.2. The enclosure regex used to check for strings ending in
    enclosure containing path separator. (CVE-2020-28469)

  - ansi-regex is vulnerable to Inefficient Regular Expression Complexity (CVE-2021-3807)

  - json-schema is vulnerable to Improperly Controlled Modification of Object Prototype Attributes ('Prototype
    Pollution') (CVE-2021-3918)

  - The normalize-url package before 4.5.1, 5.x before 5.3.1, and 6.x before 6.0.1 for Node.js has a ReDoS
    (regular expression denial of service) issue because it has exponential performance for data: URLs.
    (CVE-2021-33502)

  - The parser in accepts requests with a space (SP) right after the header name before the colon. This can
    lead to HTTP Request Smuggling (HRS) in llhttp < v2.1.4 and < v6.0.6. (CVE-2021-22959)

  - The parse function in llhttp < 2.1.4 and < 6.0.6. ignores chunk extensions when parsing the body of
    chunked requests. This leads to HTTP Request Smuggling (HRS) under certain conditions. (CVE-2021-22960)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-5171.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3918");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:npm");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/nodejs');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:16');
if ('16' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module nodejs:' + module_ver);

var appstreams = {
    'nodejs:16': [
      {'reference':'nodejs-16.13.1-3.0.1.module+el8.5.0+20457+52828f44', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-16.13.1-3.0.1.module+el8.5.0+20457+52828f44', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-16.13.1-3.0.1.module+el8.5.0+20457+52828f44', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-16.13.1-3.0.1.module+el8.5.0+20457+52828f44', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-docs-16.13.1-3.0.1.module+el8.5.0+20457+52828f44', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-16.13.1-3.0.1.module+el8.5.0+20457+52828f44', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-16.13.1-3.0.1.module+el8.5.0+20457+52828f44', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-nodemon-2.0.15-1.module+el8.5.0+20457+52828f44', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nodejs-packaging-25-1.module+el8.5.0+20388+4b61e68d', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'npm-8.1.2-1.16.13.1.3.0.1.module+el8.5.0+20457+52828f44', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'npm-8.1.2-1.16.13.1.3.0.1.module+el8.5.0+20457+52828f44', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
};

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
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:16');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-devel / nodejs-docs / etc');
}
