#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132770);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-11044",
    "CVE-2019-11045",
    "CVE-2019-11046",
    "CVE-2019-11047",
    "CVE-2019-11050"
  );

  script_name(english:"PHP 7.2.x < 7.2.26 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.2.x prior to 7.2.26. It is, therefore, affected by
multiple vulnerabilities:

  - An arbitrary file read vulnerability exists in link() and 
    DirectoryIterator class due to improper handling of embedded 
    \0 byte character and treats them as terminating at that byte. 
    An attacker can exploit this to disclose information in 
    applications checking paths that the code is allowed to access.
    (CVE-2019-11044 CVE-2019-11045)

  - An out-of-bounds READ error exists in the bcmath extension due to
    an input validation error. An unauthenticated, remote attacker 
    can exploit this by supplying a string containing characters that
    are identified as numeric by the OS but are not ASCII number. 
    This can cause lead to the disclosure of information within some
    memory locations. (CVE-2019-11046)

  - An out-of-bounds READ error exists in parsing EXIF information 
    from an image. An unauthenticated, remote attacker 
    can exploit this and supply it iwth data that will cause it to 
    read past the allocated buffer disclosing of information.
    (CVE-2019-11047)");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.2.26");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.2.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11050");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-11046");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}
include('http.inc');
include('vcf.inc');
include('audit.inc');

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');

if ((report_paranoia < 2) && backported) audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [
    {'min_version':'7.2.0alpha1', 'fixed_version':'7.2.26'}
    ];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
