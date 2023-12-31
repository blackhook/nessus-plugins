#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200907-04.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39775);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2009-1191", "CVE-2009-1195", "CVE-2009-1890", "CVE-2009-1891");
  script_bugtraq_id(34663, 35115, 35565, 35623);
  script_xref(name:"GLSA", value:"200907-04");

  script_name(english:"GLSA-200907-04 : Apache: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200907-04
(Apache: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in the Apache HTTP
    server:
    Jonathan Peatfield reported that the
    'Options=IncludesNoEXEC' argument to the 'AllowOverride' directive is
    not processed properly (CVE-2009-1195).
    Sander de Boer
    discovered that the AJP proxy module (mod_proxy_ajp) does not correctly
    handle POST requests that do not contain a request body
    (CVE-2009-1191).
    The vendor reported that the HTTP proxy
    module (mod_proxy_http), when being used as a reverse proxy, does not
    properly handle requests containing more data as stated in the
    'Content-Length' header (CVE-2009-1890).
    Francois Guerraz
    discovered that mod_deflate does not abort the compression of large
    files even when the requesting connection is closed prematurely
    (CVE-2009-1891).
  
Impact :

    A local attacker could circumvent restrictions put up by the server
    administrator and execute arbitrary commands with the privileges of the
    user running the Apache server. A remote attacker could send multiple
    requests to a server with the AJP proxy module, possibly resulting in
    the disclosure of a request intended for another client, or cause a
    Denial of Service by sending specially crafted requests to servers
    running mod_proxy_http or mod_deflate.
  
Workaround :

    Remove 'include', 'proxy_ajp', 'proxy_http' and 'deflate' from
    APACHE2_MODULES in make.conf and rebuild Apache, or disable the
    aforementioned modules in the Apache configuration."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200907-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-servers/apache-2.2.11-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/13");
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

if (qpkg_check(package:"www-servers/apache", unaffected:make_list("ge 2.2.11-r2"), vulnerable:make_list("lt 2.2.11-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache");
}
