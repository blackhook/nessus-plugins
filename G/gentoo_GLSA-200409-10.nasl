#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-10.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14669);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"GLSA", value:"200409-10");

  script_name(english:"GLSA-200409-10 : multi-gnome-terminal: Information leak");
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
"The remote host is affected by the vulnerability described in GLSA-200409-10
(multi-gnome-terminal: Information leak)

    multi-gnome-terminal contains debugging code that has been known to output
    active keystrokes to a potentially unsafe location. Output has been seen to
    show up in the '.xsession-errors' file in the user's home directory. Since
    this file is world-readable on many machines, this bug has the potential to
    leak sensitive information to anyone using the system.
  
Impact :

    Any authorized user on the local machine has the ability to read any
    critical data that has been entered into the terminal, including passwords.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All multi-gnome-terminal users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=x11-terms/multi-gnome-terminal-1.6.2-r1'
    # emerge '>=x11-terms/multi-gnome-terminal-1.6.2-r1'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:multi-gnome-terminal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"x11-terms/multi-gnome-terminal", unaffected:make_list("ge 1.6.2-r1"), vulnerable:make_list("lt 1.6.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "multi-gnome-terminal");
}
