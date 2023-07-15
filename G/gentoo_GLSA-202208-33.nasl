#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-33.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164319);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/21");

  script_cve_id("CVE-2020-12825");

  script_name(english:"GLSA-202208-33 : Gnome Shell, gettext, libcroco: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-33 (Gnome Shell, gettext, libcroco: Multiple
Vulnerabilities)

  - libcroco through 0.6.13 has excessive recursion in cr_parser_parse_any_core in cr-parser.c, leading to
    stack consumption. (CVE-2020-12825)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-33");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=722752");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=755848");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=769998");
  script_set_attribute(attribute:"solution", value:
"All gettext users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=sys-devel/gettext-0.21
        
All Gnome Shell users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=gnome-base/gnome-shell-3.36.7
        
All libcroco users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-libs/libcroco-0.6.13");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12825");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libcroco");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "dev-libs/libcroco",
    'unaffected' : make_list("ge 0.6.13"),
    'vulnerable' : make_list("lt 0.6.13")
  },
  {
    'name' : "gnome-base/gnome-shell",
    'unaffected' : make_list("ge 3.36.7"),
    'vulnerable' : make_list("lt 3.36.7")
  },
  {
    'name' : "sys-devel/gettext",
    'unaffected' : make_list("ge 0.21"),
    'vulnerable' : make_list("lt 0.21")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Gnome Shell / gettext / libcroco");
}
