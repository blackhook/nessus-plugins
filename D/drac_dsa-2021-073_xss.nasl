#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148955);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-21542");
  script_xref(name:"IAVA", value:"2021-A-0186");

  script_name(english:"Dell iDRAC XSS (DSA-2021-073)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"Dell EMC iDRAC9 versions prior to 4.40.10.00 contain a reflected cross-site scripting vulnerability in
the iDRAC9 web application. A remote authenticated malicious user with high privileges may potentially 
exploit these vulnerabilities to store malicious HTML or JavaScript code through multiple affected 
while generating a certificate. When victim users access the submitted data through their browsers, 
the malicious code gets executed by the web browser in the context of the vulnerable application.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000185293/dsa-2021-073-dell-emc-idrac-9-security-update-for-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3c31d3d");
  script_set_attribute(attribute:"solution", value:
"Update the remote host to iDRAC9 firmware 4.40.10.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21542");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac9");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drac_detect.nasl");
  script_require_keys("installed_sw/iDRAC");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('http.inc');

port = get_http_port(default:443, embedded:TRUE);

app_info = vcf::idrac::get_app_info(port:port);

constraints = [{'idrac':'9', 'min_version':'1.0', 'fixed_version':'4.40.10.00', 'fixed_display':'4.40.10.00 or later'}];

vcf::idrac::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{xss:TRUE});
