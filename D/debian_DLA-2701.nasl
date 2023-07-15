#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2701. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151368);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2020-16587",
    "CVE-2021-3474",
    "CVE-2021-3475",
    "CVE-2021-3476",
    "CVE-2021-3477",
    "CVE-2021-3478",
    "CVE-2021-3479",
    "CVE-2021-3598",
    "CVE-2021-20296",
    "CVE-2021-23215",
    "CVE-2021-26260"
  );

  script_name(english:"Debian DLA-2701-1 : openexr - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2701 advisory.

  - A heap-based buffer overflow vulnerability exists in Academy Software Foundation OpenEXR 2.3.0 in
    chunkOffsetReconstruction in ImfMultiPartInputFile.cpp that can cause a denial of service via a crafted
    EXR file. (CVE-2020-16587)

  - A flaw was found in OpenEXR in versions before 3.0.0-beta. A crafted input file supplied by an attacker,
    that is processed by the Dwa decompression functionality of OpenEXR's IlmImf library, could cause a NULL
    pointer dereference. The highest threat from this vulnerability is to system availability.
    (CVE-2021-20296)

  - An integer overflow leading to a heap-buffer overflow was found in the DwaCompressor of OpenEXR in
    versions before 3.0.1. An attacker could use this flaw to crash an application compiled with OpenEXR.
    (CVE-2021-23215)

  - An integer overflow leading to a heap-buffer overflow was found in the DwaCompressor of OpenEXR in
    versions before 3.0.1. An attacker could use this flaw to crash an application compiled with OpenEXR. This
    is a different flaw from CVE-2021-23215. (CVE-2021-26260)

  - There's a flaw in OpenEXR in versions before 3.0.0-beta. A crafted input file that is processed by OpenEXR
    could cause a shift overflow in the FastHufDecoder, potentially leading to problems with application
    availability. (CVE-2021-3474)

  - There is a flaw in OpenEXR in versions before 3.0.0-beta. An attacker who can submit a crafted file to be
    processed by OpenEXR could cause an integer overflow, potentially leading to problems with application
    availability. (CVE-2021-3475)

  - A flaw was found in OpenEXR's B44 uncompression functionality in versions before 3.0.0-beta. An attacker
    who is able to submit a crafted file to OpenEXR could trigger shift overflows, potentially affecting
    application availability. (CVE-2021-3476)

  - There's a flaw in OpenEXR's deep tile sample size calculations in versions before 3.0.0-beta. An attacker
    who is able to submit a crafted file to be processed by OpenEXR could trigger an integer overflow,
    subsequently leading to an out-of-bounds read. The greatest risk of this flaw is to application
    availability. (CVE-2021-3477)

  - There's a flaw in OpenEXR's scanline input file functionality in versions before 3.0.0-beta. An attacker
    able to submit a crafted file to be processed by OpenEXR could consume excessive system memory. The
    greatest impact of this flaw is to system availability. (CVE-2021-3478)

  - There's a flaw in OpenEXR's Scanline API functionality in versions before 3.0.0-beta. An attacker who is
    able to submit a crafted file to be processed by OpenEXR could trigger excessive consumption of memory,
    resulting in an impact to system availability. (CVE-2021-3479)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=986796");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openexr");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2701");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-16587");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20296");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23215");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-26260");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3474");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3475");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3476");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3477");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3478");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3479");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3598");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/openexr");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openexr packages.

For Debian 9 stretch, these problems have been fixed in version 2.2.0-11+deb9u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3476");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3598");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenexr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenexr22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openexr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openexr-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'libopenexr-dev', 'reference': '2.2.0-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libopenexr22', 'reference': '2.2.0-11+deb9u3'},
    {'release': '9.0', 'prefix': 'openexr', 'reference': '2.2.0-11+deb9u3'},
    {'release': '9.0', 'prefix': 'openexr-doc', 'reference': '2.2.0-11+deb9u3'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenexr-dev / libopenexr22 / openexr / openexr-doc');
}
