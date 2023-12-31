#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200411-14.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15648);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-1034");
  script_xref(name:"GLSA", value:"200411-14");

  script_name(english:"GLSA-200411-14 : Kaffeine, gxine: Remotely exploitable buffer overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200411-14
(Kaffeine, gxine: Remotely exploitable buffer overflow)

    KF of Secure Network Operations has discovered an overflow that occurs
    during the Content-Type header processing of Kaffeine. The vulnerable
    code in Kaffeine is reused from gxine, making gxine vulnerable as well.
  
Impact :

    An attacker could create a specially crafted Content-type header from a
    malicious HTTP server, and crash a user's instance of Kaffeine or
    gxine, potentially allowing the execution of arbitrary code.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://securitytracker.com/alerts/2004/Oct/1011936.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://securitytracker.com/id/1011936"
  );
  # http://sourceforge.net/tracker/index.php?func=detail&aid=1060299&group_id=9655&atid=109655
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87cfcad6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200411-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Kaffeine users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/kaffeine-0.4.3b-r1'
    All gxine users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/gxine-0.3.3-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gxine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kaffeine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/08");
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

if (qpkg_check(package:"media-video/gxine", unaffected:make_list("ge 0.3.3-r1"), vulnerable:make_list("lt 0.3.3-r1"))) flag++;
if (qpkg_check(package:"media-video/kaffeine", unaffected:make_list("ge 0.5_rc1-r1", "rge 0.4.3b-r1"), vulnerable:make_list("lt 0.5_rc1-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Kaffeine / gxine");
}
