#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200506-13.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18520);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-1707");
  script_xref(name:"GLSA", value:"200506-13");

  script_name(english:"GLSA-200506-13 : webapp-config: Insecure temporary file handling");
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
"The remote host is affected by the vulnerability described in GLSA-200506-13
(webapp-config: Insecure temporary file handling)

    Eric Romang discovered webapp-config uses a predictable temporary
    filename while processing certain options, resulting in a race
    condition.
  
Impact :

    Successful exploitation of the race condition would allow an attacker
    to disrupt the operation of webapp-config, or execute arbitrary shell
    commands with the privileges of the user running webapp-config. A local
    attacker could use a symlink attack to create or overwrite files with
    the permissions of the user running webapp-config.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200506-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All webapp-config users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-admin/webapp-config-1.11'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webapp-config");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-admin/webapp-config", unaffected:make_list("ge 1.11"), vulnerable:make_list("lt 1.11"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webapp-config");
}
