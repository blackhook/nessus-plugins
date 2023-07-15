#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-b9b15ebaad
#

include('compat.inc');

if (description)
{
  script_id(177986);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id(
    "CVE-2023-3482",
    "CVE-2023-37201",
    "CVE-2023-37202",
    "CVE-2023-37203",
    "CVE-2023-37204",
    "CVE-2023-37205",
    "CVE-2023-37206",
    "CVE-2023-37207",
    "CVE-2023-37208",
    "CVE-2023-37209",
    "CVE-2023-37210",
    "CVE-2023-37211",
    "CVE-2023-37212"
  );
  script_xref(name:"FEDORA", value:"2023-b9b15ebaad");
  script_xref(name:"IAVA", value:"2023-A-0328");

  script_name(english:"Fedora 38 : firefox (2023-b9b15ebaad)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-b9b15ebaad advisory.

  - When Firefox is configured to block storage of all cookies, it was still possible to store data in
    localstorage by using an iframe with a source of 'about:blank'. This could have led to malicious websites
    storing tracking data without permission.  (CVE-2023-3482)

  - An attacker could have triggered a use-after-free condition when creating a WebRTC connection over HTTPS.
    (CVE-2023-37201)

  - Cross-compartment wrappers wrapping a scripted proxy could have caused objects from other compartments to
    be stored in the main compartment resulting in a use-after-free.  (CVE-2023-37202)

  - Insufficient validation in the Drag and Drop API in conjunction with social engineering, may have allowed
    an attacker to trick end-users into creating a shortcut to local system files.  This could have been
    leveraged to execute arbitrary code.  (CVE-2023-37203)

  - A website could have obscured the fullscreen notification by using an option element by introducing lag
    via an expensive computational function. This could have led to user confusion and possible spoofing
    attacks.  (CVE-2023-37204)

  - The use of RTL Arabic characters in the address bar may have allowed for URL spoofing.  (CVE-2023-37205)

  - Uploading files which contain symlinks may have allowed an attacker to trick a user into submitting
    sensitive data to a malicious website.  (CVE-2023-37206)

  - A website could have obscured the fullscreen notification by using a URL with a scheme handled by an
    external program, such as a mailto URL. This could have led to user confusion and possible spoofing
    attacks.  (CVE-2023-37207)

  - When opening Diagcab files, Firefox did not warn the user that these files may contain malicious code.
    (CVE-2023-37208)

  - A use-after-free condition existed in `NotifyOnHistoryReload` where a `LoadingSessionHistoryEntry` object
    was freed and a reference to that object remained.  This resulted in a potentially exploitable condition
    when the reference to that object was later reused.  (CVE-2023-37209)

  - A website could prevent a user from exiting full-screen mode via alert and prompt calls.  This could lead
    to user confusion and possible spoofing attacks.  (CVE-2023-37210)

  - Memory safety bugs present in Firefox 114, Firefox ESR 102.12, and Thunderbird 102.12. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code.  (CVE-2023-37211)

  - Memory safety bugs present in Firefox 114. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2023-37212)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-b9b15ebaad");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-37211");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'firefox-115.0-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox');
}
