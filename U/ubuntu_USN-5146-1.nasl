#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5146-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155308);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-38493");
  script_xref(name:"USN", value:"5146-1");
  script_xref(name:"IAVA", value:"2021-A-0405");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.04 : Thunderbird vulnerabilities (USN-5146-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.04 host has packages installed that are affected by a vulnerability as
referenced in the USN-5146-1 advisory.

  - Mozilla developers reported memory safety bugs present in Firefox 91 and Firefox ESR 78.13. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 78.14, Thunderbird < 78.14,
    and Firefox < 92. (CVE-2021-38493)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5146-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38493");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ta-lk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-mozsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-calendar-timezones");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-gdata-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-lightning");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'thunderbird', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-dev', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-cak', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-cy', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-dsb', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fa', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hsb', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-kab', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-kk', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ms', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-th', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-uz', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:78.14.0+build1-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-dev', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-cak', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-cy', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-dsb', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fa', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-hsb', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-kab', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-kk', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ms', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-th', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-uz', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:78.14.0+build1-0ubuntu0.20.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-dev', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-cak', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-cy', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-dsb', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-fa', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-hsb', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-kab', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-kk', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ms', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-th', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-uz', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'},
    {'osver': '21.04', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:78.14.0+build1-0ubuntu0.21.04.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird / thunderbird-dev / thunderbird-gnome-support / etc');
}
