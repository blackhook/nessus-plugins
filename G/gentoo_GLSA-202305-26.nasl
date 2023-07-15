#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-26.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(176194);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/21");

  script_cve_id(
    "CVE-2021-21898",
    "CVE-2021-21899",
    "CVE-2021-21900",
    "CVE-2021-45341",
    "CVE-2021-45342",
    "CVE-2021-45343"
  );

  script_name(english:"GLSA-202305-26 : LibreCAD: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-26 (LibreCAD: Multiple Vulnerabilities)

  - A code execution vulnerability exists in the dwgCompressor::decompress18() functionality of LibreCad
    libdxfrw 2.2.0-rc2-19-ge02f3580. A specially-crafted .dwg file can lead to an out-of-bounds write. An
    attacker can provide a malicious file to trigger this vulnerability. (CVE-2021-21898)

  - A code execution vulnerability exists in the dwgCompressor::copyCompBytes21 functionality of LibreCad
    libdxfrw 2.2.0-rc2-19-ge02f3580. A specially-crafted .dwg file can lead to a heap buffer overflow. An
    attacker can provide a malicious file to trigger this vulnerability. (CVE-2021-21899)

  - A code execution vulnerability exists in the dxfRW::processLType() functionality of LibreCad libdxfrw
    2.2.0-rc2-19-ge02f3580. A specially-crafted .dxf file can lead to a use-after-free vulnerability. An
    attacker can provide a malicious file to trigger this vulnerability. (CVE-2021-21900)

  - A buffer overflow vulnerability in CDataMoji of the jwwlib component of LibreCAD 2.2.0-rc3 and older
    allows an attacker to achieve Remote Code Execution using a crafted JWW document. (CVE-2021-45341)

  - A buffer overflow vulnerability in CDataList of the jwwlib component of LibreCAD 2.2.0-rc3 and older
    allows an attacker to achieve Remote Code Execution using a crafted JWW document. (CVE-2021-45342)

  - In LibreCAD 2.2.0, a NULL pointer dereference in the HATCH handling of libdxfrw allows an attacker to
    crash the application using a crafted DXF document. (CVE-2021-45343)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-26");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=825362");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=832210");
  script_set_attribute(attribute:"solution", value:
"All LibreCAD users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-gfx/librecad-2.1.3-r7");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45341");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:librecad");
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
    'name' : 'media-gfx/librecad',
    'unaffected' : make_list("ge 2.1.3-r7"),
    'vulnerable' : make_list("lt 2.1.3-r7")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibreCAD');
}
