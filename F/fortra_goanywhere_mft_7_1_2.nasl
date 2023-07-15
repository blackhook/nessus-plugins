#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171771);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id("CVE-2023-0669");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/03");

  script_name(english:"Fortra GoAnywhere Managed File Transfer (MFT) < 7.1.2 Pre-Authentication Command Injection (CVE-2023-0669)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Fortra GoAnywhere Managed File Transfer (MFT) running on the
remote web server is < 7.1.2. It is, therefore, affected by a pre-authentication command injection vulnerability
in the License Response Servlet due to deserializing an arbitrary attacker-controlled object. This can allow an
unauthenticated attacker with access to the administration port to run arbitrary commands on the remote server.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://my.goanywhere.com/webclient/ViewSecurityAdvisories.xhtml#zerodayfeb1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82e61179");
  # https://attackerkb.com/topics/mg883Nbeva/cve-2023-0669/rapid7-analysis
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d6a7794");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortra GoAnywhere Managed File Transfer (MFT) 7.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0669");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Fortra GoAnywhere MFT Unsafe Deserialization RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:helpsystems:goanywhere_managed_file_transfer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortra_goanywhere_mft_web_detect.nbin");
  script_require_keys("installed_sw/Fortra GoAnywhere MFT");
  script_require_ports("Services/www", 80, 443, 8000);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:8080);

var app_info = vcf::get_app_info(app:'Fortra GoAnywhere MFT', port:port, webapp:TRUE);

var constraints = [
  {'fixed_version':'7.1.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);