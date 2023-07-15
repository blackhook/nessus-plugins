#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5384. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(174046);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id(
    "CVE-2022-36354",
    "CVE-2022-41639",
    "CVE-2022-41649",
    "CVE-2022-41684",
    "CVE-2022-41794",
    "CVE-2022-41837",
    "CVE-2022-41838",
    "CVE-2022-41977",
    "CVE-2022-41981",
    "CVE-2022-41988",
    "CVE-2022-41999",
    "CVE-2022-43592",
    "CVE-2022-43593",
    "CVE-2022-43594",
    "CVE-2022-43595",
    "CVE-2022-43596",
    "CVE-2022-43597",
    "CVE-2022-43598",
    "CVE-2022-43599",
    "CVE-2022-43600",
    "CVE-2022-43601",
    "CVE-2022-43602",
    "CVE-2022-43603"
  );

  script_name(english:"Debian DSA-5384-1 : openimageio - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5384 advisory.

  - A heap out-of-bounds read vulnerability exists in the RLA format parser of OpenImageIO master-
    branch-9aeece7a and v2.3.19.0. More specifically, in the way run-length encoded byte spans are handled. A
    malformed RLA file can lead to an out-of-bounds read of heap metadata which can result in sensitive
    information leak. An attacker can provide a malicious file to trigger this vulnerability. (CVE-2022-36354)

  - A heap based buffer overflow vulnerability exists in tile decoding code of TIFF image parser in
    OpenImageIO master-branch-9aeece7a and v2.3.19.0. A specially-crafted TIFF file can lead to an out of
    bounds memory corruption, which can result in arbitrary code execution. An attacker can provide a
    malicious file to trigger this vulnerability. (CVE-2022-41639)

  - A heap out of bounds read vulnerability exists in the handling of IPTC data while parsing TIFF images in
    OpenImageIO v2.3.19.0. A specially-crafted TIFF file can cause a read of adjacent heap memory, which can
    leak sensitive process information. An attacker can provide a malicious file to trigger this
    vulnerability. (CVE-2022-41649)

  - A heap out of bounds read vulnerability exists in the OpenImageIO master-branch-9aeece7a when parsing the
    image file directory part of a PSD image file. A specially-crafted .psd file can cause a read of arbitrary
    memory address which can lead to denial of service. An attacker can provide a malicious file to trigger
    this vulnerability. (CVE-2022-41684)

  - A heap based buffer overflow vulnerability exists in the PSD thumbnail resource parsing code of
    OpenImageIO 2.3.19.0. A specially-crafted PSD file can lead to arbitrary code execution. An attacker can
    provide a malicious file to trigger this vulnerability. (CVE-2022-41794)

  - An out-of-bounds write vulnerability exists in the OpenImageIO::add_exif_item_to_spec functionality of
    OpenImageIO Project OpenImageIO v2.4.4.2. Specially-crafted exif metadata can lead to stack-based memory
    corruption. An attacker can provide a malicious file to trigger this vulnerability. (CVE-2022-41837)

  - A code execution vulnerability exists in the DDS scanline parsing functionality of OpenImageIO Project
    OpenImageIO v2.4.4.2. A specially-crafted .dds can lead to a heap buffer overflow. An attacker can provide
    a malicious file to trigger this vulnerability. (CVE-2022-41838)

  - An out of bounds read vulnerability exists in the way OpenImageIO version v2.3.19.0 processes string
    fields in TIFF image files. A specially-crafted TIFF file can lead to information disclosure. An attacker
    can provide a malicious file to trigger this vulnerability. (CVE-2022-41977)

  - A stack-based buffer overflow vulnerability exists in the TGA file format parser of OpenImageIO v2.3.19.0.
    A specially-crafted targa file can lead to out of bounds read and write on the process stack, which can
    lead to arbitrary code execution. An attacker can provide a malicious file to trigger this vulnerability.
    (CVE-2022-41981)

  - An information disclosure vulnerability exists in the OpenImageIO::decode_iptc_iim() functionality of
    OpenImageIO Project OpenImageIO v2.3.19.0. A specially-crafted TIFF file can lead to a disclosure of
    sensitive information. An attacker can provide a malicious file to trigger this vulnerability.
    (CVE-2022-41988)

  - A denial of service vulnerability exists in the DDS native tile reading functionality of OpenImageIO
    Project OpenImageIO v2.3.19.0 and v2.4.4.2. A specially-crafted .dds can lead to denial of service. An
    attacker can provide a malicious file to trigger this vulnerability. (CVE-2022-41999)

  - An information disclosure vulnerability exists in the DPXOutput::close() functionality of OpenImageIO
    Project OpenImageIO v2.4.4.2. A specially crafted ImageOutput Object can lead to leaked heap data. An
    attacker can provide malicious input to trigger this vulnerability. (CVE-2022-43592)

  - A denial of service vulnerability exists in the DPXOutput::close() functionality of OpenImageIO Project
    OpenImageIO v2.4.4.2. A specially crafted ImageOutput Object can lead to null pointer dereference. An
    attacker can provide malicious input to trigger this vulnerability. (CVE-2022-43593)

  - Multiple denial of service vulnerabilities exist in the image output closing functionality of OpenImageIO
    Project OpenImageIO v2.4.4.2. Specially crafted ImageOutput Objects can lead to multiple null pointer
    dereferences. An attacker can provide malicious multiple inputs to trigger these vulnerabilities.This
    vulnerability applies to writing .bmp files. (CVE-2022-43594)

  - Multiple denial of service vulnerabilities exist in the image output closing functionality of OpenImageIO
    Project OpenImageIO v2.4.4.2. Specially crafted ImageOutput Objects can lead to multiple null pointer
    dereferences. An attacker can provide malicious multiple inputs to trigger these vulnerabilities.This
    vulnerability applies to writing .fits files. (CVE-2022-43595)

  - An information disclosure vulnerability exists in the IFFOutput channel interleaving functionality of
    OpenImageIO Project OpenImageIO v2.4.4.2. A specially crafted ImageOutput Object can lead to leaked heap
    data. An attacker can provide malicious input to trigger this vulnerability. (CVE-2022-43596)

  - Multiple memory corruption vulnerabilities exist in the IFFOutput alignment padding functionality of
    OpenImageIO Project OpenImageIO v2.4.4.2. A specially crafted ImageOutput Object can lead to arbitrary
    code execution. An attacker can provide malicious input to trigger these vulnerabilities.This
    vulnerability arises when the `m_spec.format` is `TypeDesc::UINT8`. (CVE-2022-43597)

  - Multiple memory corruption vulnerabilities exist in the IFFOutput alignment padding functionality of
    OpenImageIO Project OpenImageIO v2.4.4.2. A specially crafted ImageOutput Object can lead to arbitrary
    code execution. An attacker can provide malicious input to trigger these vulnerabilities.This
    vulnerability arises when the `m_spec.format` is `TypeDesc::UINT16`. (CVE-2022-43598)

  - Multiple code execution vulnerabilities exist in the IFFOutput::close() functionality of OpenImageIO
    Project OpenImageIO v2.4.4.2. A specially crafted ImageOutput Object can lead to a heap buffer overflow.
    An attacker can provide malicious input to trigger these vulnerabilities.This vulnerability arises when
    the `xmax` variable is set to 0xFFFF and `m_spec.format` is `TypeDesc::UINT8` (CVE-2022-43599)

  - Multiple code execution vulnerabilities exist in the IFFOutput::close() functionality of OpenImageIO
    Project OpenImageIO v2.4.4.2. A specially crafted ImageOutput Object can lead to a heap buffer overflow.
    An attacker can provide malicious input to trigger these vulnerabilities.This vulnerability arises when
    the `xmax` variable is set to 0xFFFF and `m_spec.format` is `TypeDesc::UINT16` (CVE-2022-43600)

  - Multiple code execution vulnerabilities exist in the IFFOutput::close() functionality of OpenImageIO
    Project OpenImageIO v2.4.4.2. A specially crafted ImageOutput Object can lead to a heap buffer overflow.
    An attacker can provide malicious input to trigger these vulnerabilities.This vulnerability arises when
    the `ymax` variable is set to 0xFFFF and `m_spec.format` is `TypeDesc::UINT16` (CVE-2022-43601)

  - Multiple code execution vulnerabilities exist in the IFFOutput::close() functionality of OpenImageIO
    Project OpenImageIO v2.4.4.2. A specially crafted ImageOutput Object can lead to a heap buffer overflow.
    An attacker can provide malicious input to trigger these vulnerabilities.This vulnerability arises when
    the `ymax` variable is set to 0xFFFF and `m_spec.format` is `TypeDesc::UINT8` (CVE-2022-43602)

  - A denial of service vulnerability exists in the ZfileOutput::close() functionality of OpenImageIO Project
    OpenImageIO v2.4.4.2. A specially crafted ImageOutput Object can lead to denial of service. An attacker
    can provide a malicious file to trigger this vulnerability. (CVE-2022-43603)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1027143");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openimageio");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5384");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36354");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41639");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41649");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41684");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41794");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41837");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41838");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41977");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41981");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41988");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41999");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43592");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43593");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43594");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43595");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43596");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43599");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43600");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43602");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43603");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/openimageio");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openimageio packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.2.10.1+dfsg-1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41838");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenimageio-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenimageio-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenimageio2.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openimageio-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-openimageio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libopenimageio-dev', 'reference': '2.2.10.1+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libopenimageio-doc', 'reference': '2.2.10.1+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libopenimageio2.2', 'reference': '2.2.10.1+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'openimageio-tools', 'reference': '2.2.10.1+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'python3-openimageio', 'reference': '2.2.10.1+dfsg-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenimageio-dev / libopenimageio-doc / libopenimageio2.2 / etc');
}
