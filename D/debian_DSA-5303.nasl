#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5303. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168880);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id(
    "CVE-2022-45414",
    "CVE-2022-46872",
    "CVE-2022-46874",
    "CVE-2022-46878",
    "CVE-2022-46880",
    "CVE-2022-46881",
    "CVE-2022-46882"
  );
  script_xref(name:"IAVA", value:"2022-A-0519-S");
  script_xref(name:"IAVA", value:"2022-A-0505-S");
  script_xref(name:"IAVA", value:"2023-A-0009-S");

  script_name(english:"Debian DSA-5303-1 : thunderbird - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5303 advisory.

  - Mozilla: Quoting from an HTML email with certain tags will trigger network requests and load remote
    content, regardless of a configuration to block remote content (CVE-2022-45414)

  - An attacker who compromised a content process could have partially escaped the sandbox to read arbitrary
    files via clipboard-related IPC messages. This bug only affects Thunderbird for Linux. Other operating
    systems are unaffected.  (CVE-2022-46872)

  - A file with a long filename could have had its filename truncated to remove the valid extension, leaving a
    malicious extension in its place. This could potentially led to user confusion and the execution of
    malicious code.  (CVE-2022-46874)

  - Mozilla developers Randell Jesup, Valentin Gosu, Olli Pettay, and the Mozilla Fuzzing Team reported memory
    safety bugs present in Firefox 107 and Firefox ESR 102.5. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code.  (CVE-2022-46878)

  - A missing check related to tex units could have led to a use-after-free and potentially exploitable crash.
    (CVE-2022-46880)

  - An optimization in WebGL was incorrect in some cases, and could have led to memory corruption and a
    potentially exploitable crash.  (CVE-2022-46881)

  - A use-after-free in WebGL extensions could have led to a potentially exploitable crash.  (CVE-2022-46882)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/thunderbird");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5303");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45414");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-46872");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-46874");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-46878");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-46880");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-46881");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-46882");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/thunderbird");
  script_set_attribute(attribute:"solution", value:
"Upgrade the thunderbird packages.

For the stable distribution (bullseye), this problem has been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-en-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-hy-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'thunderbird', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-af', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-all', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-ar', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-ast', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-be', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-bg', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-br', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-ca', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-cak', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-cs', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-cy', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-da', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-de', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-dsb', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-el', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-en-ca', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-en-gb', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-es-ar', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-es-es', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-et', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-eu', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-fi', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-fr', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-fy-nl', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-ga-ie', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-gd', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-gl', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-he', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-hr', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-hsb', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-hu', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-hy-am', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-id', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-is', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-it', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-ja', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-ka', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-kab', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-kk', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-ko', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-lt', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-lv', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-ms', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-nb-no', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-nl', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-nn-no', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-pa-in', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-pl', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-pt-br', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-pt-pt', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-rm', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-ro', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-ru', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-sk', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-sl', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-sq', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-sr', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-sv-se', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-th', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-tr', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-uk', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-uz', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-vi', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-zh-cn', 'reference': '1:102.6.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'thunderbird-l10n-zh-tw', 'reference': '1:102.6.0-1~deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird / thunderbird-l10n-af / thunderbird-l10n-all / etc');
}
