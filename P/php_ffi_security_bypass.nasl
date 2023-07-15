#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17714);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-4528");
  script_xref(name:"EDB-ID", value:"4311");

  script_name(english:"PHP Foreign Function Interface Arbitrary DLL Loading safe_mode Restriction Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is affected by a security bypass vulnerability.  The Foreign
Function Interface (ffi) extension does not follow safe_mode
restrictions, which allows context-dependent attackers to execute
arbitrary code by loading an arbitrary DLL and calling a function.");
  script_set_attribute(attribute:"see_also", value:"http://pecl.php.net/package-info.php?package=ffi");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-4528");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "Settings/PCI_DSS", "installed_sw/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

# Only PCI considers this an issue.
if (!get_kb_item('Settings/PCI_DSS')) audit(AUDIT_PCI);

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');

if ((report_paranoia < 2) && backported) audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [ {'min_version':'5.0.5alpha1', 'fixed_version':'5.1.0'} ];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
