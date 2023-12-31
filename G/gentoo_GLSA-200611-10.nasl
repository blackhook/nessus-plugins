#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200611-10.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(23675);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2006-5705");
  script_xref(name:"GLSA", value:"200611-10");

  script_name(english:"GLSA-200611-10 : WordPress: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200611-10
(WordPress: Multiple vulnerabilities)

    'random' discovered that users can enter serialized objects as strings
    in their profiles that will be harmful when unserialized. 'adapter'
    found out that user-edit.php fails to effectively deny non-permitted
    users access to other user's metadata. Additionally, a directory
    traversal vulnerability in the wp-db-backup module was discovered.
  
Impact :

    By entering specially crafted strings in his profile, an attacker can
    crash PHP or even the web server running WordPress. Additionally, by
    crafting a simple URL, an attacker can read metadata of any other user,
    regardless of their own permissions. A user with the permission to use
    the database backup plugin can possibly overwrite files he otherwise
    has no access to.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://trac.wordpress.org/ticket/3142
  script_set_attribute(
    attribute:"see_also",
    value:"https://core.trac.wordpress.org/ticket/3142"
  );
  # http://trac.wordpress.org/ticket/2591
  script_set_attribute(
    attribute:"see_also",
    value:"https://core.trac.wordpress.org/ticket/2591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200611-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All WordPress users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/wordpress-2.0.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/20");
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

if (qpkg_check(package:"www-apps/wordpress", unaffected:make_list("ge 2.0.5"), vulnerable:make_list("lt 2.0.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "WordPress");
}
