#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3204. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168183);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/24");

  script_cve_id(
    "CVE-2022-0318",
    "CVE-2022-0392",
    "CVE-2022-0629",
    "CVE-2022-0696",
    "CVE-2022-1619",
    "CVE-2022-1621",
    "CVE-2022-1785",
    "CVE-2022-1897",
    "CVE-2022-1942",
    "CVE-2022-2000",
    "CVE-2022-2129",
    "CVE-2022-3235",
    "CVE-2022-3256",
    "CVE-2022-3352"
  );

  script_name(english:"Debian DLA-3204-1 : vim - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3204 advisory.

  - Heap-based Buffer Overflow in vim/vim prior to 8.2. (CVE-2022-0318)

  - Heap-based Buffer Overflow in GitHub repository vim prior to 8.2. (CVE-2022-0392)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0629)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.4428. (CVE-2022-0696)

  - Heap-based Buffer Overflow in function cmdline_erase_chars in GitHub repository vim/vim prior to 8.2.4899.
    This vulnerabilities are capable of crashing software, modify memory, and possible remote execution
    (CVE-2022-1619)

  - Heap buffer overflow in vim_strncpy find_word in GitHub repository vim/vim prior to 8.2.4919. This
    vulnerability is capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible
    remote execution (CVE-2022-1621)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.4977. (CVE-2022-1785)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2. (CVE-2022-1897, CVE-2022-2000,
    CVE-2022-2129)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-1942)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0490. (CVE-2022-3235)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0530. (CVE-2022-3256)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0614. (CVE-2022-3352)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/vim");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3204");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0318");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0392");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0629");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0696");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1619");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1621");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1785");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1897");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1942");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2000");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2129");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3235");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3256");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3352");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/vim");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vim packages.

For Debian 10 buster, these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0318");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-athena");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gui-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-tiny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xxd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'vim', 'reference': '2:8.1.0875-5+deb10u4'},
    {'release': '10.0', 'prefix': 'vim-athena', 'reference': '2:8.1.0875-5+deb10u4'},
    {'release': '10.0', 'prefix': 'vim-common', 'reference': '2:8.1.0875-5+deb10u4'},
    {'release': '10.0', 'prefix': 'vim-doc', 'reference': '2:8.1.0875-5+deb10u4'},
    {'release': '10.0', 'prefix': 'vim-gtk', 'reference': '2:8.1.0875-5+deb10u4'},
    {'release': '10.0', 'prefix': 'vim-gtk3', 'reference': '2:8.1.0875-5+deb10u4'},
    {'release': '10.0', 'prefix': 'vim-gui-common', 'reference': '2:8.1.0875-5+deb10u4'},
    {'release': '10.0', 'prefix': 'vim-nox', 'reference': '2:8.1.0875-5+deb10u4'},
    {'release': '10.0', 'prefix': 'vim-runtime', 'reference': '2:8.1.0875-5+deb10u4'},
    {'release': '10.0', 'prefix': 'vim-tiny', 'reference': '2:8.1.0875-5+deb10u4'},
    {'release': '10.0', 'prefix': 'xxd', 'reference': '2:8.1.0875-5+deb10u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'vim / vim-athena / vim-common / vim-doc / vim-gtk / vim-gtk3 / etc');
}
