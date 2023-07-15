#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156193);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2021-43014");
  script_xref(name:"IAVB", value:"2021-B-0070-S");

  script_name(english:"Adobe Connect <= 11.3 Arbitrary File System Write Vulnerability (APSB21-112)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
a arbitrary file system write vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect installed on the remote host is prior to 11.4. It is, therefore, affected by a
vulnerability as referenced in the apsb21-112 advisory.

  - Cross-Site Request Forgery (CSRF) (CWE-352) potentially leading to Arbitrary file system write
    (CVE-2021-43014)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/352.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb21-112.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 11.4 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:connect");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_connect_detect.nbin");
  script_require_keys("installed_sw/Adobe Connect");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:'Adobe Connect', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '11', 'max_version' : '11.3', 'fixed_version' : '11.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE}
);
