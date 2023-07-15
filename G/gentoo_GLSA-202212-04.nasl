#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202212-04.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(168910);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/18");

  script_cve_id("CVE-2022-3140");

  script_name(english:"GLSA-202212-04 : LibreOffice: Arbitrary Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202212-04 (LibreOffice: Arbitrary Code Execution)

  - LibreOffice supports Office URI Schemes to enable browser integration of LibreOffice with MS SharePoint
    server. An additional scheme 'vnd.libreoffice.command' specific to LibreOffice was added. In the affected
    versions of LibreOffice links using that scheme could be constructed to call internal macros with
    arbitrary arguments. Which when clicked on, or activated by document events, could result in arbitrary
    script execution without warning. This issue affects: The Document Foundation LibreOffice 7.4 versions
    prior to 7.4.1; 7.3 versions prior to 7.3.6. (CVE-2022-3140)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202212-04");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=876869");
  script_set_attribute(attribute:"solution", value:
"All LibreOffice users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-office/libreoffice-7.3.6.2
        
All LibreOffice binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-office/libreoffice-bin-7.3.6.2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3140");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libreoffice-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'app-office/libreoffice',
    'unaffected' : make_list("ge 7.3.6.2"),
    'vulnerable' : make_list("lt 7.3.6.2")
  },
  {
    'name' : 'app-office/libreoffice-bin',
    'unaffected' : make_list("ge 7.3.6.2"),
    'vulnerable' : make_list("lt 7.3.6.2")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibreOffice');
}
