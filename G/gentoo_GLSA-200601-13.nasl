#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200601-13.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20815);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2006-0330");
  script_xref(name:"GLSA", value:"200601-13");

  script_name(english:"GLSA-200601-13 : Gallery: XSS vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200601-13
(Gallery: XSS vulnerability)

    Peter Schumacher discovered that Gallery fails to sanitize the
    fullname set by users, possibly leading to a cross-site scripting
    vulnerability.
  
Impact :

    By setting a specially crafted fullname, an attacker can inject
    and execute script code in the victim's browser window and potentially
    compromise the user's gallery.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://gallery.menalto.com/page/gallery_1_5_2_release
  script_set_attribute(
    attribute:"see_also",
    value:"http://galleryproject.org/page/gallery_1_5_2_release"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200601-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Gallery users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/gallery-1.5.2'
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gallery");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"www-apps/gallery", unaffected:make_list("ge 1.5.2"), vulnerable:make_list("lt 1.5.2"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Gallery");
}
