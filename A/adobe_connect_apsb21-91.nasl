#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154144);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/28");

  script_cve_id("CVE-2021-40719", "CVE-2021-40721");
  script_xref(name:"IAVB", value:"2021-B-0058-S");

  script_name(english:"Adobe Connect < 11.2.3 Multiple Vulnerabilities (APSB21-91)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect running on the remote host is 11.2.2 or earlier. It is, therefore, affected by multiple 
vulnerabilities. 

  - An unsafe deserialization vulnerability exists in Adobe Connect. An unauthenticated, remote attacker can exploit 
    this to execute arbitrary code on the target host. (CVE-2021-40719)

  - A reflected cross-site scripting (XSS) vulnerability exists in Adobe Connect due to improper validation of 
    user-supplied input before returning it to users. An unauthenticated, remote attacker can exploit this, by 
    convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's browser session.
    (CVE-2021-40721)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb21-91.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 11.2.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40719");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:connect");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_connect_detect.nbin");
  script_require_keys("installed_sw/Adobe Connect");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:80);
var app_info = vcf::get_app_info(app:'Adobe Connect', port:port, webapp:TRUE);

var constraints = [{'fixed_version' : '11.2.3'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);