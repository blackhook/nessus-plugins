#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5145. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161494);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id(
    "CVE-2018-5786",
    "CVE-2020-25467",
    "CVE-2021-27345",
    "CVE-2021-27347",
    "CVE-2022-26291",
    "CVE-2022-28044"
  );

  script_name(english:"Debian DSA-5145-1 : lrzip - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dsa-5145 advisory.

  - In Long Range Zip (aka lrzip) 0.631, there is an infinite loop and application hang in the get_fileinfo
    function (lrzip.c). Remote attackers could leverage this vulnerability to cause a denial of service via a
    crafted lrz file. (CVE-2018-5786)

  - A null pointer dereference was discovered lzo_decompress_buf in stream.c in Irzip 0.621 which allows an
    attacker to cause a denial of service (DOS) via a crafted compressed file. (CVE-2020-25467)

  - A null pointer dereference was discovered in ucompthread in stream.c in Irzip 0.631 which allows attackers
    to cause a denial of service (DOS) via a crafted compressed file. (CVE-2021-27345)

  - Use after free in lzma_decompress_buf function in stream.c in Irzip 0.631 allows attackers to cause Denial
    of Service (DoS) via a crafted compressed file. (CVE-2021-27347)

  - lrzip v0.641 was discovered to contain a multiple concurrency use-after-free between the functions
    zpaq_decompress_buf() and clear_rulist(). This vulnerability allows attackers to cause a Denial of Service
    (DoS) via a crafted Irz file. (CVE-2022-26291)

  - Irzip v0.640 was discovered to contain a heap memory corruption via the component
    lrzip.c:initialise_control. (CVE-2022-28044)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/lrzip");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5145");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5786");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25467");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-27345");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-27347");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26291");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28044");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/lrzip");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/lrzip");
  script_set_attribute(attribute:"solution", value:
"Upgrade the lrzip packages.

For the stable distribution (bullseye), these problems have been fixed in version 0.641-1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28044");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lrzip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'lrzip', 'reference': '0.631+git180528-1+deb10u1'},
    {'release': '11.0', 'prefix': 'lrzip', 'reference': '0.641-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lrzip');
}
