#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200412-01.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15903);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-1161", "CVE-2004-1162");
  script_xref(name:"GLSA", value:"200412-01");

  script_name(english:"GLSA-200412-01 : rssh, scponly: Unrestricted command execution");
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
"The remote host is affected by the vulnerability described in GLSA-200412-01
(rssh, scponly: Unrestricted command execution)

    Jason Wies discovered that when receiving an authorized command from an
    authorized user, rssh and scponly do not filter command-line options
    that can be used to execute any command on the target host.
  
Impact :

    Using a malicious command, it is possible for a remote authenticated
    user to execute any command (or upload and execute any file) on the
    target machine with user rights, effectively bypassing any restriction
    of scponly or rssh.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.securityfocus.com/archive/1/383046/2004-11-30/2004-12-06/0
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/archive/1/383046/2004-11-30/2004-12-06/0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200412-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All scponly users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/scponly-4.0'
    All rssh users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-shells/rssh/rssh-2.2.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:scponly");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"net-misc/scponly", unaffected:make_list("ge 4.0"), vulnerable:make_list("lt 4.0"))) flag++;
if (qpkg_check(package:"app-shells/rssh", unaffected:make_list("ge 2.2.3"), vulnerable:make_list("le 2.2.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rssh / scponly");
}
