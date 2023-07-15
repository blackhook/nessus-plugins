#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201310-21.
#
# The advisory text is Copyright (C) 2001-2019 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70677);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2013-1816", "CVE-2013-1817", "CVE-2013-1818", "CVE-2013-1951", "CVE-2013-2031", "CVE-2013-2032", "CVE-2013-2114", "CVE-2013-4301", "CVE-2013-4302", "CVE-2013-4303", "CVE-2013-4304", "CVE-2013-4305", "CVE-2013-4306", "CVE-2013-4307", "CVE-2013-4308");
  script_bugtraq_id(58304, 58305, 58306, 59077, 59594, 59595, 60077, 62194, 62201, 62202, 62203, 62210, 62215, 62218, 62434);
  script_xref(name:"GLSA", value:"201310-21");

  script_name(english:"GLSA-201310-21 : MediaWiki: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201310-21
(MediaWiki: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MediaWiki. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker may be able to execute arbitrary code, perform
      man-in-the-middle attacks, obtain sensitive information or perform
      cross-site scripting attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201310-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MediaWiki 1.21.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/mediawiki-1.21.2'
    All MediaWiki 1.20.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/mediawiki-1.20.7'
    All MediaWiki 1.19.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/mediawiki-1.19.8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-apps/mediawiki", unaffected:make_list("ge 1.21.2", "rge 1.20.7", "rge 1.19.8"), vulnerable:make_list("lt 1.21.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MediaWiki");
}
