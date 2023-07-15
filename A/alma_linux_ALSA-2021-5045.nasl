#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:5045.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157549);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id(
    "CVE-2021-43528",
    "CVE-2021-43536",
    "CVE-2021-43537",
    "CVE-2021-43538",
    "CVE-2021-43539",
    "CVE-2021-43541",
    "CVE-2021-43542",
    "CVE-2021-43543",
    "CVE-2021-43545",
    "CVE-2021-43546"
  );
  script_xref(name:"ALSA", value:"2021:5045");
  script_xref(name:"IAVA", value:"2021-A-0569-S");

  script_name(english:"AlmaLinux 8 : thunderbird (ALSA-2021:5045)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ALSA-2021:5045 advisory.

  - Thunderbird unexpectedly enabled JavaScript in the composition area. The JavaScript execution context was
    limited to this area and did not receive chrome-level privileges, but could be used as a stepping stone to
    further an attack with other vulnerabilities. This vulnerability affects Thunderbird < 91.4.0.
    (CVE-2021-43528)

  - Under certain circumstances, asynchronous functions could have caused a navigation to fail but expose the
    target URL. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95.
    (CVE-2021-43536)

  - An incorrect type conversion of sizes from 64bit to 32bit integers allowed an attacker to corrupt memory
    leading to a potentially exploitable crash. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR <
    91.4.0, and Firefox < 95. (CVE-2021-43537)

  - By misusing a race in our notification code, an attacker could have forcefully hidden the notification for
    pages that had received full screen and pointer lock access, which could have been used for spoofing
    attacks. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95.
    (CVE-2021-43538)

  - Failure to correctly record the location of live pointers across wasm instance calls resulted in a GC
    occurring within the call not tracing those live pointers. This could have led to a use-after-free causing
    a potentially exploitable crash. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0,
    and Firefox < 95. (CVE-2021-43539)

  - When invoking protocol handlers for external protocols, a supplied parameter URL containing spaces was not
    properly escaped. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95.
    (CVE-2021-43541)

  - Using XMLHttpRequest, an attacker could have identified installed applications by probing error messages
    for loading external protocols. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and
    Firefox < 95. (CVE-2021-43542)

  - Documents loaded with the CSP sandbox directive could have escaped the sandbox's script restriction by
    embedding additional content. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and
    Firefox < 95. (CVE-2021-43543)

  - Using the Location API in a loop could have caused severe application hangs and crashes. This
    vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95. (CVE-2021-43545)

  - It was possible to recreate previous cursor spoofing attacks against users with a zoomed native cursor.
    This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95. (CVE-2021-43546)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-5045.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected thunderbird package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43539");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'thunderbird-91.4.0-2.el8_5.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird');
}
