#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201412-28.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79981);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2010-3933", "CVE-2011-0446", "CVE-2011-0447", "CVE-2011-0448", "CVE-2011-0449", "CVE-2011-2929", "CVE-2011-2930", "CVE-2011-2931", "CVE-2011-2932", "CVE-2011-3186", "CVE-2013-0155", "CVE-2013-0156", "CVE-2013-0276", "CVE-2013-0277", "CVE-2013-0333", "CVE-2013-1854", "CVE-2013-1855", "CVE-2013-1856", "CVE-2013-1857");
  script_bugtraq_id(44124, 46291, 46292, 49179, 57187, 57192, 57575, 57896, 57898, 58549, 58552, 58554, 58555);
  script_xref(name:"GLSA", value:"201412-28");

  script_name(english:"GLSA-201412-28 : Ruby on Rails: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201412-28
(Ruby on Rails: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Ruby on Rails. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could execute arbitrary code or cause a Denial of
      Service condition. Furthermore, a remote attacker may be able to execute
      arbitrary SQL commands, change parameter names for form inputs and make
      changes to arbitrary records in the system, bypass intended access
      restrictions, render arbitrary views, inject arbitrary web script or
      HTML, or conduct cross-site request forgery (CSRF) attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201412-28"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Ruby on Rails 2.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-ruby/rails-2.3.18'
    NOTE: All applications using Ruby on Rails should also be configured to
      use the latest version available by running &ldquo;rake rails:update&rdquo;
      inside the application directory.
    NOTE: This is a legacy GLSA and stable updates for Ruby on Rails,
      including the unaffected version listed above, are no longer available
      from Gentoo. It may be possible to upgrade to the 3.2, 4.0, or 4.1
      branches, however these packages are not currently stable."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails JSON Processor YAML Deserialization Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rails");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"dev-ruby/rails", unaffected:make_list("ge 2.3.18"), vulnerable:make_list("lt 2.3.18"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ruby on Rails");
}
