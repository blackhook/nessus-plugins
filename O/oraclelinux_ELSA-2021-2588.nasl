#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-2588.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151449);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/07");

  script_cve_id(
    "CVE-2019-3881",
    "CVE-2019-15845",
    "CVE-2019-16201",
    "CVE-2019-16254",
    "CVE-2019-16255",
    "CVE-2020-10663",
    "CVE-2020-10933",
    "CVE-2020-25613",
    "CVE-2021-28965"
  );

  script_name(english:"Oracle Linux 8 : ruby:2.6 (ELSA-2021-2588)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-2588 advisory.

  - The JSON gem through 2.2.0 for Ruby, as used in Ruby 2.4 through 2.4.9, 2.5 through 2.5.7, and 2.6 through
    2.6.5, has an Unsafe Object Creation Vulnerability. This is quite similar to CVE-2013-0269, but does not
    rely on poor garbage-collection behavior within Ruby. Specifically, use of JSON parsing methods can lead
    to creation of a malicious object within the interpreter, with adverse effects that are application-
    dependent. (CVE-2020-10663)

  - Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 mishandles path checking within
    File.fnmatch functions. (CVE-2019-15845)

  - WEBrick::HTTPAuth::DigestAuth in Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 has a
    regular expression Denial of Service cause by looping/backtracking. A victim must expose a WEBrick server
    that uses DigestAuth to the Internet or a untrusted network. (CVE-2019-16201)

  - Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 allows HTTP Response Splitting. If a
    program using WEBrick inserts untrusted input into the response header, an attacker can exploit it to
    insert a newline character to split a header, and inject malicious content to deceive clients. NOTE: this
    issue exists because of an incomplete fix for CVE-2017-17742, which addressed the CRLF vector, but did not
    address an isolated CR or an isolated LF. (CVE-2019-16254)

  - Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 allows code injection if the first
    argument (aka the command argument) to Shell#[] or Shell#test in lib/shell.rb is untrusted data. An
    attacker can exploit this to call an arbitrary Ruby method. (CVE-2019-16255)

  - An issue was discovered in Ruby through 2.5.8, 2.6.x through 2.6.6, and 2.7.x through 2.7.1. WEBrick, a
    simple HTTP server bundled with Ruby, had not checked the transfer-encoding header value rigorously. An
    attacker may potentially exploit this issue to bypass a reverse proxy (which also has a poor header
    check), which may lead to an HTTP Request Smuggling attack. (CVE-2020-25613)

  - An issue was discovered in Ruby 2.5.x through 2.5.7, 2.6.x through 2.6.5, and 2.7.0. If a victim calls
    BasicSocket#read_nonblock(requested_size, buffer, exception: false), the method resizes the buffer to fit
    the requested size, but no data is copied. Thus, the buffer string provides the previous value of the
    heap. This may expose possibly sensitive data from the interpreter. (CVE-2020-10933)

  - The REXML gem before 3.2.5 in Ruby before 2.6.7, 2.7.x before 2.7.3, and 3.x before 3.0.1 does not
    properly address XML round-trip issues. An incorrect document can be produced after parsing and
    serializing. (CVE-2021-28965)

  - Bundler prior to 2.1.0 uses a predictable path in /tmp/, created with insecure permissions as a storage
    location for gems, if locations under the user's home directory are not available. If Bundler is used in a
    scenario where the user does not have a writable home directory, an attacker could place malicious code in
    this directory that would be later loaded and executed. (CVE-2019-3881)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-2588.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-bson-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-mongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygems-devel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

module_ver = get_kb_item('Host/RedHat/appstream/ruby');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.6');
if ('2.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module ruby:' + module_ver);

appstreams = {
    'ruby:2.6': [
      {'reference':'ruby-2.6.7-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-2.6.7-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-2.6.7-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-2.6.7-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-2.6.7-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-2.6.7-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-doc-2.6.7-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-2.6.7-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-2.6.7-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-2.6.7-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-abrt-0.3.0-4.module+el8.1.0+5406+ce01f9b9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-abrt-doc-0.3.0-4.module+el8.1.0+5406+ce01f9b9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-1.4.1-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-1.4.1-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-1.4.1-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bson-4.5.0-1.module+el8.4.0+20235+1e5b8be3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bson-4.5.0-1.module+el8.4.0+20235+1e5b8be3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bson-doc-4.5.0-1.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bundler-1.17.2-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-did_you_mean-1.3.0-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.4.7-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.4.7-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.4.7-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-irb-1.0.0-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.1.0-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.1.0-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.1.0-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-minitest-5.11.3-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mongo-2.8.0-1.module+el8.1.0+5406+ce01f9b9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mongo-doc-2.8.0-1.module+el8.1.0+5406+ce01f9b9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-0.5.2-1.module+el8.4.0+20235+1e5b8be3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-0.5.2-1.module+el8.4.0+20235+1e5b8be3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-doc-0.5.2-1.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-net-telnet-0.2.0-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-openssl-2.1.2-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-openssl-2.1.2-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-openssl-2.1.2-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-1.1.4-1.module+el8.4.0+20235+1e5b8be3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-1.1.4-1.module+el8.4.0+20235+1e5b8be3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-doc-1.1.4-1.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-power_assert-1.1.3-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-3.1.0-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-3.1.0-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-3.1.0-107.module+el8.4.0+20235+1e5b8be3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rake-12.3.3-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rdoc-6.1.2-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-test-unit-3.2.9-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-xmlrpc-0.3.0-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-3.0.3.1-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-devel-3.0.3.1-107.module+el8.4.0+20235+1e5b8be3', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.6');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-devel / ruby-doc / etc');
}
