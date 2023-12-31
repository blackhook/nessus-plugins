#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200707-06.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25719);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-2194");
  script_xref(name:"GLSA", value:"200707-06");

  script_name(english:"GLSA-200707-06 : XnView: Stack-based buffer overflow");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200707-06
(XnView: Stack-based buffer overflow)

    XnView is vulnerable to a stack-based buffer overflow while processing
    an XPM file with an overly long section string (greater than 1024
    bytes).
  
Impact :

    An attacker could entice a user to view a specially crafted XPM file
    with XnView that could trigger the vulnerability and possibly execute
    arbitrary code with the rights of the user running XnView.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200707-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"No update appears to be forthcoming from the XnView developer and
    XnView is proprietary, so the XnView package has been masked in
    Portage. We recommend that users select an alternate graphics viewer
    and conversion utility, and unmerge XnView:
    # emerge --unmerge xnview"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xnview");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list", "Host/Gentoo/arch");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);
ourarch = get_kb_item("Host/Gentoo/arch");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86)$") audit(AUDIT_ARCH_NOT, "x86", ourarch);

flag = 0;

if (qpkg_check(package:"x11-misc/xnview", arch:"x86", unaffected:make_list(), vulnerable:make_list("lt 1.70"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "XnView");
}
