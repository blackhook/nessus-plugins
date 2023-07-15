##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:4887.
##

include('compat.inc');

if (description)
{
  script_id(162853);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-1834",
    "CVE-2022-31736",
    "CVE-2022-31737",
    "CVE-2022-31738",
    "CVE-2022-31740",
    "CVE-2022-31741",
    "CVE-2022-31742",
    "CVE-2022-31747"
  );
  script_xref(name:"RLSA", value:"2022:4887");
  script_xref(name:"IAVA", value:"2022-A-0226-S");

  script_name(english:"Rocky Linux 8 : thunderbird (RLSA-2022:4887)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2022:4887 advisory.

  - Mozilla developers Andrew McCreight, Nicolas B. Pierron, and the Mozilla Fuzzing Team reported memory
    safety bugs present in Firefox 100 and Firefox ESR 91.9. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code. This vulnerability affects Thunderbird < 91.10, Firefox < 101, and Firefox ESR < 91.10.
    (CVE-2022-31747)

  - When displaying the sender of an email, and the sender name contained the Braille Pattern Blank space
    character multiple times, Thunderbird would have displayed all the spaces. This could have been used by an
    attacker to send an email message with the attacker's digital signature, that was shown with an arbitrary
    sender email address chosen by the attacker. If the sender name started with a false email address,
    followed by many Braille space characters, the attacker's email address was not visible. Because
    Thunderbird compared the invisible sender address with the signature's email address, if the signing key
    or certificate was accepted by Thunderbird, the email was shown as having a valid digital signature. This
    vulnerability affects Thunderbird < 91.10. (CVE-2022-1834)

  - A malicious website could have learned the size of a cross-origin resource that supported Range requests.
    This vulnerability affects Thunderbird < 91.10, Firefox < 101, and Firefox ESR < 91.10. (CVE-2022-31736)

  - A malicious webpage could have caused an out-of-bounds write in WebGL, leading to memory corruption and a
    potentially exploitable crash. This vulnerability affects Thunderbird < 91.10, Firefox < 101, and Firefox
    ESR < 91.10. (CVE-2022-31737)

  - When exiting fullscreen mode, an iframe could have confused the browser about the current state of
    fullscreen, resulting in potential user confusion or spoofing attacks. This vulnerability affects
    Thunderbird < 91.10, Firefox < 101, and Firefox ESR < 91.10. (CVE-2022-31738)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:4887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092416");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31747");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:firefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:thunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RockyLinux/release');
if (isnull(release) || 'Rocky Linux' >!< release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'firefox-91.10.0-1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-91.10.0-1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-debuginfo-91.10.0-1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-debuginfo-91.10.0-1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-debugsource-91.10.0-1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-debugsource-91.10.0-1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-91.10.0-1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-91.10.0-1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-91.10.0-1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-91.10.0-1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debugsource-91.10.0-1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debugsource-91.10.0-1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  if (!empty_or_null(package_array['release'])) release = 'Rocky-' + package_array['release'];
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox / firefox-debuginfo / firefox-debugsource / thunderbird / etc');
}
