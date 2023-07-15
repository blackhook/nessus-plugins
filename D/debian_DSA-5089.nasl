#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5089. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158684);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/10");

  script_cve_id(
    "CVE-2022-0789",
    "CVE-2022-0790",
    "CVE-2022-0791",
    "CVE-2022-0792",
    "CVE-2022-0793",
    "CVE-2022-0794",
    "CVE-2022-0795",
    "CVE-2022-0796",
    "CVE-2022-0797",
    "CVE-2022-0798",
    "CVE-2022-0799",
    "CVE-2022-0800",
    "CVE-2022-0801",
    "CVE-2022-0802",
    "CVE-2022-0803",
    "CVE-2022-0804",
    "CVE-2022-0805",
    "CVE-2022-0806",
    "CVE-2022-0807",
    "CVE-2022-0808",
    "CVE-2022-0809"
  );

  script_name(english:"Debian DSA-5089-1 : chromium - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5089 advisory.

  - Use after free in Chrome OS Shell in Google Chrome on Chrome OS prior to 99.0.4844.51 allowed a remote
    attacker who convinced a user to engage in a series of user interaction to potentially exploit heap
    corruption via user interactions. (CVE-2022-0808)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0789)

  - Use after free in Cast UI in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who convinced a
    user to engage in specific user interaction to potentially perform a sandbox escape via a crafted HTML
    page. (CVE-2022-0790)

  - Use after free in Omnibox in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who convinced a
    user to engage in specific user interactions to potentially exploit heap corruption via user interactions.
    (CVE-2022-0791)

  - Out of bounds read in ANGLE in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0792)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/chromium");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5089");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0789");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0790");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0791");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0792");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0793");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0794");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0795");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0796");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0797");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0798");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0799");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0800");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0801");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0803");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0804");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0805");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0806");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0807");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0808");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0809");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/chromium");
  script_set_attribute(attribute:"solution", value:
"Upgrade the chromium packages.

For the stable distribution (bullseye), these problems have been fixed in version 99.0.4844.51-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0809");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0790");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-shell");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'chromium', 'reference': '99.0.4844.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-common', 'reference': '99.0.4844.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-driver', 'reference': '99.0.4844.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-l10n', 'reference': '99.0.4844.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-sandbox', 'reference': '99.0.4844.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-shell', 'reference': '99.0.4844.51-1~deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium / chromium-common / chromium-driver / chromium-l10n / etc');
}
