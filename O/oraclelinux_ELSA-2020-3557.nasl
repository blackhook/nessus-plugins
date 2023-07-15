#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-3557.
#

include('compat.inc');

if (description)
{
  script_id(140042);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/25");

  script_cve_id(
    "CVE-2020-12422",
    "CVE-2020-12424",
    "CVE-2020-12425",
    "CVE-2020-15648",
    "CVE-2020-15653",
    "CVE-2020-15654",
    "CVE-2020-15656",
    "CVE-2020-15658",
    "CVE-2020-15664",
    "CVE-2020-15669"
  );
  script_xref(name:"IAVA", value:"2020-A-0391-S");

  script_name(english:"Oracle Linux 8 : firefox (ELSA-2020-3557)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ELSA-2020-3557 advisory.

  - In non-standard configurations, a JPEG image created by JavaScript could have caused an internal variable
    to overflow, resulting in an out of bounds write, memory corruption, and a potentially exploitable crash.
    This vulnerability affects Firefox < 78. (CVE-2020-12422)

  - When constructing a permission prompt for WebRTC, a URI was supplied from the content process. This URI
    was untrusted, and could have been the URI of an origin that was previously granted permission; bypassing
    the prompt. This vulnerability affects Firefox < 78. (CVE-2020-12424)

  - Due to confusion processing a hyphen character in Date.parse(), a one-byte out of bounds read could have
    occurred, leading to potential information disclosure. This vulnerability affects Firefox < 78.
    (CVE-2020-12425)

  - Using object or embed tags, it was possible to frame other websites, even if they disallowed framing using
    the X-Frame-Options header. This vulnerability affects Thunderbird < 78 and Firefox < 78.0.2.
    (CVE-2020-15648)

  - An iframe sandbox element with the allow-popups flag could be bypassed when using noopener links. This
    could have led to security issues for websites relying on sandbox configurations that allowed popups and
    hosted arbitrary content. This vulnerability affects Firefox ESR < 78.1, Firefox < 79, and Thunderbird <
    78.1. (CVE-2020-15653)

  - When in an endless loop, a website specifying a custom cursor using CSS could make it look like the user
    is interacting with the user interface, when they are not. This could lead to a perceived broken state,
    especially when interactions with existing browser dialogs and warnings do not work. This vulnerability
    affects Firefox ESR < 78.1, Firefox < 79, and Thunderbird < 78.1. (CVE-2020-15654)

  - JIT optimizations involving the Javascript arguments object could confuse later optimizations. This risk
    was already mitigated by various precautions in the code, resulting in this bug rated at only moderate
    severity. This vulnerability affects Firefox ESR < 78.1, Firefox < 79, and Thunderbird < 78.1.
    (CVE-2020-15656)

  - The code for downloading files did not properly take care of special characters, which led to an attacker
    being able to cut off the file ending at an earlier position, leading to a different file type being
    downloaded than shown in the dialog. This vulnerability affects Firefox ESR < 78.1, Firefox < 79, and
    Thunderbird < 78.1. (CVE-2020-15658)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://linux.oracle.com/errata/ELSA-2020-3557.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15656");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = [
    {'reference':'firefox-78.2.0-2.0.1.el8_2', 'cpu':'aarch64', 'release':'8', 'allowmaj':TRUE},
    {'reference':'firefox-78.2.0-2.0.1.el8_2', 'cpu':'x86_64', 'release':'8', 'allowmaj':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox');
}
