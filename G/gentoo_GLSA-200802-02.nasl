#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200802-02.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(30244);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-4642", "CVE-2007-4643", "CVE-2007-4644");
  script_xref(name:"GLSA", value:"200802-02");

  script_name(english:"GLSA-200802-02 : Doomsday: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200802-02
(Doomsday: Multiple vulnerabilities)

    Luigi Auriemma discovered multiple buffer overflows in the
    D_NetPlayerEvent() function, the Msg_Write() function and the
    NetSv_ReadCommands() function. He also discovered errors when handling
    chat messages that are not NULL-terminated (CVE-2007-4642) or contain a
    short data length, triggering an integer underflow (CVE-2007-4643).
    Furthermore a format string vulnerability was discovered in the
    Cl_GetPackets() function when processing PSV_CONSOLE_TEXT messages
    (CVE-2007-4644).
  
Impact :

    A remote attacker could exploit these vulnerabilities to execute
    arbitrary code with the rights of the user running the Doomsday server
    or cause a Denial of Service by sending specially crafted messages to
    the server.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200802-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"While some of these issues could be resolved in
    'games-fps/doomsday-1.9.0-beta5.2', the format string vulnerability
    (CVE-2007-4644) remains unfixed. We recommend that users unmerge
    Doomsday:
    # emerge --unmerge games-fps/doomsday"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:doomsday");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"games-fps/doomsday", unaffected:make_list(), vulnerable:make_list("le 1.9.0_beta52"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Doomsday");
}
