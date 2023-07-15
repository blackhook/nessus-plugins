#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-33.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(176473);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/30");

  script_cve_id(
    "CVE-2022-4198",
    "CVE-2022-36354",
    "CVE-2022-38143",
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

  script_name(english:"GLSA-202305-33 : OpenImageIO: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-33 (OpenImageIO: Multiple Vulnerabilities)

  - The WP Social Sharing WordPress plugin through 2.2 does not sanitise and escape some of its settings,
    which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even
    when the unfiltered_html capability is disallowed (for example in multisite setup). (CVE-2022-4198)

  - A heap out-of-bounds read vulnerability exists in the RLA format parser of OpenImageIO master-
    branch-9aeece7a and v2.3.19.0. More specifically, in the way run-length encoded byte spans are handled. A
    malformed RLA file can lead to an out-of-bounds read of heap metadata which can result in sensitive
    information leak. An attacker can provide a malicious file to trigger this vulnerability. (CVE-2022-36354)

  - A heap out-of-bounds write vulnerability exists in the way OpenImageIO v2.3.19.0 processes RLE encoded BMP
    images. A specially-crafted bmp file can write to arbitrary out of bounds memory, which can lead to
    arbitrary code execution. An attacker can provide a malicious file to trigger this vulnerability.
    (CVE-2022-38143)

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
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-33");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=879255");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=884085");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=888045");
  script_set_attribute(attribute:"solution", value:
"All OpenImageIO users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-libs/openimageio-2.4.6.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41838");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openimageio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'media-libs/openimageio',
    'unaffected' : make_list("ge 2.4.6.0"),
    'vulnerable' : make_list("lt 2.4.6.0")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'OpenImageIO');
}
