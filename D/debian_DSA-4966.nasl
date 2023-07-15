#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4966. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152943);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/01");

  script_cve_id(
    "CVE-2021-21834",
    "CVE-2021-21836",
    "CVE-2021-21837",
    "CVE-2021-21838",
    "CVE-2021-21839",
    "CVE-2021-21840",
    "CVE-2021-21841",
    "CVE-2021-21842",
    "CVE-2021-21843",
    "CVE-2021-21844",
    "CVE-2021-21845",
    "CVE-2021-21846",
    "CVE-2021-21847",
    "CVE-2021-21848",
    "CVE-2021-21849",
    "CVE-2021-21850",
    "CVE-2021-21853",
    "CVE-2021-21854",
    "CVE-2021-21855",
    "CVE-2021-21857",
    "CVE-2021-21858",
    "CVE-2021-21859",
    "CVE-2021-21860",
    "CVE-2021-21861"
  );

  script_name(english:"Debian DSA-4966-1 : gpac - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4966 advisory.

  - An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC
    Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input when decoding the atom for
    the co64 FOURCC can cause an integer overflow due to unchecked arithmetic resulting in a heap-based
    buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger
    this vulnerability. (CVE-2021-21834)

  - An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC
    Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input using the ctts FOURCC code
    can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that
    causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.
    (CVE-2021-21836)

  - Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of
    the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer
    overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory
    corruption. An attacker can convince a user to open a video to trigger this vulnerability.
    (CVE-2021-21837, CVE-2021-21838, CVE-2021-21839)

  - An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC
    Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input used to process an atom using
    the saio FOURCC code cause an integer overflow due to unchecked arithmetic resulting in a heap-based
    buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger
    this vulnerability. (CVE-2021-21840)

  - An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC
    Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input when reading an atom using
    the 'sbgp' FOURCC code can cause an integer overflow due to unchecked arithmetic resulting in a heap-based
    buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger
    this vulnerability. (CVE-2021-21841)

  - An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC
    Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow
    when processing an atom using the 'ssix' FOURCC code, due to unchecked arithmetic resulting in a heap-
    based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to
    trigger this vulnerability. (CVE-2021-21842)

  - Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of
    the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer
    overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory
    corruption. After validating the number of ranges, at [41] the library will multiply the count by the size
    of the GF_SubsegmentRangeInfo structure. On a 32-bit platform, this multiplication can result in an
    integer overflow causing the space of the array being allocated to be less than expected. An attacker can
    convince a user to open a video to trigger this vulnerability. (CVE-2021-21843)

  - Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of
    the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input when encountering an
    atom using the stco FOURCC code, can cause an integer overflow due to unchecked arithmetic resulting in
    a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a
    video to trigger this vulnerability. (CVE-2021-21844)

  - Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of
    the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input in stsc decoder
    can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that
    causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.
    (CVE-2021-21845)

  - Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of
    the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input in stsz decoder
    can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that
    causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.
    (CVE-2021-21846)

  - Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of
    the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input in stts decoder
    can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that
    causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.
    (CVE-2021-21847)

  - An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC
    Project on Advanced Content library v1.0.1. The library will actually reuse the parser for atoms with the
    stsz FOURCC code when parsing atoms that use the stz2 FOURCC code and can cause an integer overflow
    due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An
    attacker can convince a user to open a video to trigger this vulnerability. (CVE-2021-21848)

  - An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC
    Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow
    when the library encounters an atom using the tfra FOURCC code due to unchecked arithmetic resulting in
    a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a
    video to trigger this vulnerability. (CVE-2021-21849)

  - An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC
    Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow
    when the library encounters an atom using the trun FOURCC code due to unchecked arithmetic resulting in
    a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a
    video to trigger this vulnerability. (CVE-2021-21850)

  - Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of
    the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer
    overflow due to unchecked addition arithmetic resulting in a heap-based buffer overflow that causes memory
    corruption. An attacker can convince a user to open a video to trigger this vulnerability.
    (CVE-2021-21853, CVE-2021-21854, CVE-2021-21855, CVE-2021-21857, CVE-2021-21858)

  - An exploitable integer truncation vulnerability exists within the MPEG-4 decoding functionality of the
    GPAC Project on Advanced Content library v1.0.1. The stri_box_read function is used when processing atoms
    using the 'stri' FOURCC code. An attacker can convince a user to open a video to trigger this
    vulnerability. (CVE-2021-21859)

  - An exploitable integer truncation vulnerability exists within the MPEG-4 decoding functionality of the
    GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an improper
    memory allocation resulting in a heap-based buffer overflow that causes memory corruption. The FOURCC
    code, 'trik', is parsed by the function within the library. An attacker can convince a user to open a
    video to trigger this vulnerability. (CVE-2021-21860)

  - An exploitable integer truncation vulnerability exists within the MPEG-4 decoding functionality of the
    GPAC Project on Advanced Content library v1.0.1. When processing the 'hdlr' FOURCC code, a specially
    crafted MPEG-4 input can cause an improper memory allocation resulting in a heap-based buffer overflow
    that causes memory corruption. An attacker can convince a user to open a video to trigger this
    vulnerability. (CVE-2021-21861)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/gpac");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4966");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21834");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21836");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21837");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21838");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21839");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21840");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21841");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21842");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21843");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21844");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21845");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21846");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21847");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21848");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21849");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21850");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21853");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21854");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21855");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21857");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21858");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21859");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21860");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21861");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/gpac");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gpac packages.

For the stable distribution (bullseye), these problems have been fixed in version 1.0.1+dfsg1-4+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21861");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gpac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gpac-modules-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgpac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgpac10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'gpac', 'reference': '1.0.1+dfsg1-4+deb11u1'},
    {'release': '11.0', 'prefix': 'gpac-modules-base', 'reference': '1.0.1+dfsg1-4+deb11u1'},
    {'release': '11.0', 'prefix': 'libgpac-dev', 'reference': '1.0.1+dfsg1-4+deb11u1'},
    {'release': '11.0', 'prefix': 'libgpac10', 'reference': '1.0.1+dfsg1-4+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gpac / gpac-modules-base / libgpac-dev / libgpac10');
}
