#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200905-07.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38909);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2009-1373", "CVE-2009-1374", "CVE-2009-1375", "CVE-2009-1376");
  script_bugtraq_id(35067);
  script_xref(name:"GLSA", value:"200905-07");

  script_name(english:"GLSA-200905-07 : Pidgin: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200905-07
(Pidgin: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Pidgin:
    Veracode reported a boundary error in the 'XMPP SOCKS5 bytestream
    server' when initiating an outgoing file transfer (CVE-2009-1373).
    Ka-Hing Cheung reported a heap corruption flaw in the QQ protocol
    handler (CVE-2009-1374).
    A memory corruption flaw in
    'PurpleCircBuffer' was disclosed by Josef Andrysek
    (CVE-2009-1375).
    The previous fix for CVE-2008-2927 contains a
    cast from uint64 to size_t, possibly leading to an integer overflow
    (CVE-2009-1376, GLSA 200901-13).
  
Impact :

    A remote attacker could send specially crafted messages or files using
    the MSN, XMPP or QQ protocols, possibly resulting in the execution of
    arbitrary code with the privileges of the user running the application,
    or a Denial of Service. NOTE: Successful exploitation might require the
    victim's interaction.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200901-13"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200905-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Pidgin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/pidgin-2.5.6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"net-im/pidgin", unaffected:make_list("ge 2.5.6"), vulnerable:make_list("lt 2.5.6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Pidgin");
}
