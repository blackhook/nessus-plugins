#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92320);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-4979");
  script_bugtraq_id(91566);

  script_name(english:"Apache 2.4.18 / 2.4.20 X.509 Certificate Authentication Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache running on the remote
host is either 2.4.18 or 2.4.20. Additionally, HTTP/2 is enabled over
TLS or SSL. It is, therefore, affected by the an authentication bypass
vulnerability in the experimental module for the HTTP/2 protocol due
to a failure to correctly validate X.509 certificates, allowing access
to resources that otherwise would not be allowed. An unauthenticated,
remote attacker can exploit this to disclose potentially sensitive
information.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.23");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2016/Jul/11");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.23 or later. Alternatively, as a
temporary workaround, HTTP/2 can be disabled by changing the
configuration by removing 'h2' and 'h2c' from the Protocols line(s)
in the configuration file.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4979");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("alpn_protocol_enumeration.nasl", "apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');


app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

constraints = [
  { 'min_version' : '2.4.0', 'fixed_version' : '2.4.23' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
