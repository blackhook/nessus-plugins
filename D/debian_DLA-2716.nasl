#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2716. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152012);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/23");

  script_cve_id(
    "CVE-2020-35653",
    "CVE-2021-25290",
    "CVE-2021-28676",
    "CVE-2021-28677",
    "CVE-2021-34552"
  );

  script_name(english:"Debian DLA-2716-1 : pillow - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2716 advisory.

  - In Pillow before 8.1.0, PcxDecode has a buffer over-read when decoding a crafted PCX file because the
    user-supplied stride value is trusted for buffer calculations. (CVE-2020-35653)

  - An issue was discovered in Pillow before 8.1.1. In TiffDecode.c, there is a negative-offset memcpy with an
    invalid size. (CVE-2021-25290)

  - An issue was discovered in Pillow before 8.2.0. For FLI data, FliDecode did not properly check that the
    block advance was non-zero, potentially leading to an infinite loop on load. (CVE-2021-28676)

  - An issue was discovered in Pillow before 8.2.0. For EPS data, the readline implementation used in
    EPSImageFile has to deal with any combination of \r and \n as line endings. It used an accidentally
    quadratic method of accumulating lines while looking for a line ending. A malicious EPS file could use
    this to perform a DoS of Pillow in the open phase, before an image was accepted for opening.
    (CVE-2021-28677)

  - Pillow through 8.2.0 and PIL (aka Python Imaging Library) through 1.1.7 allow an attacker to pass
    controlled parameters directly into a convert function to trigger a buffer overflow in Convert.c.
    (CVE-2021-34552)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/pillow");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2716");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35653");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25290");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28676");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28677");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-34552");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/pillow");
  script_set_attribute(attribute:"solution", value:
"Upgrade the pillow packages.

For Debian 9 stretch, these problems have been fixed in version 4.0.0-4+deb9u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34552");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-imaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil.imagetk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil.imagetk-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil.imagetk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil.imagetk-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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

release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

pkgs = [
    {'release': '9.0', 'prefix': 'python-imaging', 'reference': '4.0.0-4+deb9u3'},
    {'release': '9.0', 'prefix': 'python-pil', 'reference': '4.0.0-4+deb9u3'},
    {'release': '9.0', 'prefix': 'python-pil-dbg', 'reference': '4.0.0-4+deb9u3'},
    {'release': '9.0', 'prefix': 'python-pil-doc', 'reference': '4.0.0-4+deb9u3'},
    {'release': '9.0', 'prefix': 'python-pil.imagetk', 'reference': '4.0.0-4+deb9u3'},
    {'release': '9.0', 'prefix': 'python-pil.imagetk-dbg', 'reference': '4.0.0-4+deb9u3'},
    {'release': '9.0', 'prefix': 'python3-pil', 'reference': '4.0.0-4+deb9u3'},
    {'release': '9.0', 'prefix': 'python3-pil-dbg', 'reference': '4.0.0-4+deb9u3'},
    {'release': '9.0', 'prefix': 'python3-pil.imagetk', 'reference': '4.0.0-4+deb9u3'},
    {'release': '9.0', 'prefix': 'python3-pil.imagetk-dbg', 'reference': '4.0.0-4+deb9u3'}
];

flag = 0;
foreach package_array ( pkgs ) {
  release = NULL;
  prefix = NULL;
  reference = NULL;
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
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-imaging / python-pil / python-pil-dbg / python-pil-doc / etc');
}
