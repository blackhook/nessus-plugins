#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200912-02.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43378);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-5380", "CVE-2007-6077", "CVE-2008-4094", "CVE-2008-7248", "CVE-2009-2422", "CVE-2009-3009", "CVE-2009-3086", "CVE-2009-4214");
  script_bugtraq_id(31176, 36278, 37142);
  script_xref(name:"GLSA", value:"200912-02");

  script_name(english:"GLSA-200912-02 : Ruby on Rails: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200912-02
(Ruby on Rails: Multiple vulnerabilities)

    The following vulnerabilities were discovered:
    sameer
    reported that lib/action_controller/cgi_process.rb removes the
    :cookie_only attribute from the default session options
    (CVE-2007-6077), due to an incomplete fix for CVE-2007-5380 (GLSA
    200711-17).
    Tobias Schlottke reported that the :limit and
    :offset parameters of ActiveRecord::Base.find() are not properly
    sanitized before being processed (CVE-2008-4094).
    Steve from
    Coderrr reported that the CRSF protection in protect_from_forgery()
    does not parse the text/plain MIME format (CVE-2008-7248).
    Nate reported a documentation error that leads to the assumption
    that a block returning nil passed to
    authenticate_or_request_with_http_digest() would deny access to the
    requested resource (CVE-2009-2422).
    Brian Mastenbrook reported
    an input sanitation flaw, related to multibyte characters
    (CVE-2009-3009).
    Gabe da Silveira reported an input sanitation
    flaw in the strip_tags() function (CVE-2009-4214).
    Coda Hale
    reported an information disclosure vulnerability related to HMAC
    digests (CVE-2009-3086).
  
Impact :

    A remote attacker could send specially crafted requests to a vulnerable
    application, possibly leading to the execution of arbitrary SQL
    statements or a circumvention of access control. A remote attacker
    could also conduct session fixation attacks to hijack a user's session
    or bypass the CSRF protection mechanism, or furthermore conduct
    Cross-Site Scripting attacks or forge a digest via multiple attempts.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200711-17"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200912-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Ruby on Rails 2.3.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-ruby/rails-2.3.5'
    All Ruby on Rails 2.2.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '=dev-ruby/rails-2.2.3-r1'
    NOTE: All applications using Ruby on Rails should also be configured to
    use the latest version available by running 'rake rails:update' inside
    the application directory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79, 89, 200, 287, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rails");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/22");
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

if (qpkg_check(package:"dev-ruby/rails", unaffected:make_list("ge 2.3.5", "rge 2.2.3-r1"), vulnerable:make_list("lt 2.2.2"))) flag++;

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
