#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144775);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2018-20843", "CVE-2019-10092", "CVE-2019-10098");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"IBM HTTP Server 7.0.0.0 <= 7.0.0.45 / 8.0.0.0 <= 8.0.0.15 / 8.5.0.0 < 8.5.5.17 / 9.0.0.0 < 9.0.5.1 Multiple Vulnerabilities (964768)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by multiple vulnerabilities as follows:

  - In libexpat in Expat before 2.2.7, XML input including XML names that contain a large number of colons
    could make the XML parser consume a high amount of RAM and CPU resources while processing (enough to be
    usable for denial-of-service attacks). (CVE-2018-20843)

  - In Apache HTTP Server 2.4.0-2.4.39, a limited cross-site scripting issue was reported affecting the 
    mod_proxy error page. An attacker could cause the link on the error page to be malformed and instead point
    to a page of their choice. This would only be exploitable where a server was set up with proxying enabled
    but was misconfigured in such a way that the Proxy Error page was displayed. (CVE-2019-10092)

  - In Apache HTTP server 2.4.0 to 2.4.39, Redirects configured with mod_rewrite that were intended to be
    self-referential might be fooled by encoded newlines and redirect instead to an unexpected URL within the
    request URL. (CVE-2019-10098)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/964768");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 8.5.5.17, 9.0.5.1, or later. Alternatively, upgrade to the minimal fix pack levels
 required by the interim fix and then apply Interim Fix PH14974.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10098");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_http_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM HTTP Server (IHS)");

  exit(0);
}


include('vcf.inc');

app = 'IBM HTTP Server (IHS)';
fix = 'Interim Fix PH14974';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PH14974' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
 { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.45', 'fixed_display' : fix },
 { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.15', 'fixed_display' : fix },
 { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.16', 'fixed_display' : '8.5.5.17 or ' + fix },
 { 'min_version' : '9.0.0.0', 'max_version' : '9.0.5.0', 'fixed_display' : '9.0.5.1 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
