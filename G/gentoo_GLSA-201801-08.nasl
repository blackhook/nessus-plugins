#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201801-08.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(105634);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2018/01/08 16:12:45 $");

  script_cve_id("CVE-2015-6031");
  script_xref(name:"GLSA", value:"201801-08");

  script_name(english:"GLSA-201801-08 : MiniUPnPc: Arbitrary code execution");
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
"The remote host is affected by the vulnerability described in GLSA-201801-08
(MiniUPnPc: Arbitrary code execution)

    An exploitable buffer overflow vulnerability exists in the XML parser
      functionality of the MiniUPnP library.
  
Impact :

    A remote attacker, by enticing a user to connect to a malicious server,
      could cause the execution of arbitrary code with the privileges of the
      user running a MiniUPnPc linked application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201801-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MiniUPnPc users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-libs/miniupnpc-2.0.20170509'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:miniupnpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-libs/miniupnpc", unaffected:make_list("ge 2.0.20170509"), vulnerable:make_list("lt 2.0.20170509"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MiniUPnPc");
}
