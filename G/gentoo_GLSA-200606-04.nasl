#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200606-04.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21671);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2006-0414");
  script_xref(name:"GLSA", value:"200606-04");

  script_name(english:"GLSA-200606-04 : Tor: Several vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200606-04
(Tor: Several vulnerabilities)

    Some integer overflows exist when adding elements to the smartlists.
    Non-printable characters received from the network are not properly
    sanitised before being logged. There are additional unspecified bugs in
    the directory server and in the internal circuits.
  
Impact :

    The possible buffer overflow may allow a remote attacker to execute
    arbitrary code on the server by sending large inputs. The other
    vulnerabilities can lead to a Denial of Service, a lack of logged
    information, or some information disclosure.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://tor.eff.org/cvs/tor/ChangeLog
  script_set_attribute(
    attribute:"see_also",
    value:"https://tor.eff.org//cvs/tor/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200606-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Tor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-misc/tor"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/08");
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

if (qpkg_check(package:"net-misc/tor", unaffected:make_list("ge 0.1.1.20", "rge 0.1.0.18"), vulnerable:make_list("lt 0.1.1.20"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Tor");
}
