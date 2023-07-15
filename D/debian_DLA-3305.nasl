#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3305. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170983);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id(
    "CVE-2018-16981",
    "CVE-2019-13217",
    "CVE-2019-13218",
    "CVE-2019-13219",
    "CVE-2019-13220",
    "CVE-2019-13221",
    "CVE-2019-13222",
    "CVE-2019-13223",
    "CVE-2021-28021",
    "CVE-2021-37789",
    "CVE-2021-42715",
    "CVE-2022-28041",
    "CVE-2022-28042"
  );

  script_name(english:"Debian DLA-3305-1 : libstb - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3305 advisory.

  - stb stb_image.h 2.19, as used in catimg, Emscripten, and other products, has a heap-based buffer overflow
    in the stbi__out_gif_code function. (CVE-2018-16981)

  - A heap buffer overflow in the start_decoder function in stb_vorbis through 2019-03-04 allows an attacker
    to cause a denial of service or execute arbitrary code by opening a crafted Ogg Vorbis file.
    (CVE-2019-13217)

  - Division by zero in the predict_point function in stb_vorbis through 2019-03-04 allows an attacker to
    cause a denial of service by opening a crafted Ogg Vorbis file. (CVE-2019-13218)

  - A NULL pointer dereference in the get_window function in stb_vorbis through 2019-03-04 allows an attacker
    to cause a denial of service by opening a crafted Ogg Vorbis file. (CVE-2019-13219)

  - Use of uninitialized stack variables in the start_decoder function in stb_vorbis through 2019-03-04 allows
    an attacker to cause a denial of service or disclose sensitive information by opening a crafted Ogg Vorbis
    file. (CVE-2019-13220)

  - A stack buffer overflow in the compute_codewords function in stb_vorbis through 2019-03-04 allows an
    attacker to cause a denial of service or execute arbitrary code by opening a crafted Ogg Vorbis file.
    (CVE-2019-13221)

  - An out-of-bounds read of a global buffer in the draw_line function in stb_vorbis through 2019-03-04 allows
    an attacker to cause a denial of service or disclose sensitive information by opening a crafted Ogg Vorbis
    file. (CVE-2019-13222)

  - A reachable assertion in the lookup1_values function in stb_vorbis through 2019-03-04 allows an attacker
    to cause a denial of service by opening a crafted Ogg Vorbis file. (CVE-2019-13223)

  - Buffer overflow vulnerability in function stbi__extend_receive in stb_image.h in stb 2.26 via a crafted
    JPEG file. (CVE-2021-28021)

  - stb_image.h 2.27 has a heap-based buffer over in stbi__jpeg_load, leading to Information Disclosure or
    Denial of Service. (CVE-2021-37789)

  - An issue was discovered in stb stb_image.h 1.33 through 2.27. The HDR loader parsed truncated end-of-file
    RLE scanlines as an infinite sequence of zero-length runs. An attacker could potentially have caused
    denial of service in applications using stb_image by submitting crafted HDR files. (CVE-2021-42715)

  - stb_image.h v2.27 was discovered to contain an integer overflow via the function
    stbi__jpeg_decode_block_prog_dc. This vulnerability allows attackers to cause a Denial of Service (DoS)
    via unspecified vectors. (CVE-2022-28041)

  - stb_image.h v2.27 was discovered to contain an heap-based use-after-free via the function
    stbi__jpeg_huff_decode. (CVE-2022-28042)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=934966");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libstb");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3305");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-16981");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13217");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13218");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13219");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13220");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13221");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13222");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13223");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28021");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37789");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42715");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28041");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28042");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libstb");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libstb packages.

For Debian 10 buster, these problems have been fixed in version 0.0~git20180212.15.e6afb9c-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstb0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'libstb-dev', 'reference': '0.0~git20180212.15.e6afb9c-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libstb0', 'reference': '0.0~git20180212.15.e6afb9c-1+deb10u1'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libstb-dev / libstb0');
}
