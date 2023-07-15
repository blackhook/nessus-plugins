#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2947. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158978);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2021-3872",
    "CVE-2021-3927",
    "CVE-2021-3928",
    "CVE-2021-3973",
    "CVE-2021-3974",
    "CVE-2021-3984",
    "CVE-2021-4019",
    "CVE-2021-4069",
    "CVE-2021-4192",
    "CVE-2021-4193",
    "CVE-2022-0213",
    "CVE-2022-0319",
    "CVE-2022-0359",
    "CVE-2022-0361",
    "CVE-2022-0368",
    "CVE-2022-0408",
    "CVE-2022-0554",
    "CVE-2022-0685",
    "CVE-2022-0714",
    "CVE-2022-0729"
  );

  script_name(english:"Debian DLA-2947-1 : vim - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2947 advisory.

  - vim is vulnerable to Heap-based Buffer Overflow (CVE-2021-3872, CVE-2021-3927, CVE-2021-3973,
    CVE-2021-3984, CVE-2021-4019, CVE-2022-0213)

  - vim is vulnerable to Use of Uninitialized Variable (CVE-2021-3928)

  - vim is vulnerable to Use After Free (CVE-2021-3974, CVE-2021-4069, CVE-2021-4192)

  - vim is vulnerable to Out-of-bounds Read (CVE-2021-4193)

  - Out-of-bounds Read in vim/vim prior to 8.2. (CVE-2022-0319)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0359, CVE-2022-0361)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-0368)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0408)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2. (CVE-2022-0554)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4418. (CVE-2022-0685)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4436. (CVE-2022-0714)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4440. (CVE-2022-0729)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/vim");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2947");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3872");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3927");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3928");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3973");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3974");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3984");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4019");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4069");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4192");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4193");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0213");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0319");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0359");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0361");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0368");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0408");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0554");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0685");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0714");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0729");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/vim");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vim packages.

For Debian 9 stretch, these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3973");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-athena");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gui-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-tiny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xxd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'vim', 'reference': '2:8.0.0197-4+deb9u5'},
    {'release': '9.0', 'prefix': 'vim-athena', 'reference': '2:8.0.0197-4+deb9u5'},
    {'release': '9.0', 'prefix': 'vim-common', 'reference': '2:8.0.0197-4+deb9u5'},
    {'release': '9.0', 'prefix': 'vim-doc', 'reference': '2:8.0.0197-4+deb9u5'},
    {'release': '9.0', 'prefix': 'vim-gnome', 'reference': '2:8.0.0197-4+deb9u5'},
    {'release': '9.0', 'prefix': 'vim-gtk', 'reference': '2:8.0.0197-4+deb9u5'},
    {'release': '9.0', 'prefix': 'vim-gtk3', 'reference': '2:8.0.0197-4+deb9u5'},
    {'release': '9.0', 'prefix': 'vim-gui-common', 'reference': '2:8.0.0197-4+deb9u5'},
    {'release': '9.0', 'prefix': 'vim-nox', 'reference': '2:8.0.0197-4+deb9u5'},
    {'release': '9.0', 'prefix': 'vim-runtime', 'reference': '2:8.0.0197-4+deb9u5'},
    {'release': '9.0', 'prefix': 'vim-tiny', 'reference': '2:8.0.0197-4+deb9u5'},
    {'release': '9.0', 'prefix': 'xxd', 'reference': '2:8.0.0197-4+deb9u5'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'vim / vim-athena / vim-common / vim-doc / vim-gnome / vim-gtk / etc');
}
