#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151291);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-35464");
  script_xref(name:"IAVA", value:"2021-A-0359-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"ForgeRock Access Management < 7.0 RCE");

  script_set_attribute(attribute:"synopsis", value:
"ForgeRock Access Management is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ForgeRock Access Management detected on the remote host is affected by a remote code execution
vulnerability due to unsafe object deserialization. An unauthenticated, remote attacker can exploit this to execute
code on the remote host.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://portswigger.net/research/pre-auth-rce-in-forgerock-openam-cve-2021-35464
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3a6dd6c");
  # https://www.rapid7.com/blog/post/2021/06/30/forgerock-openam-pre-auth-remote-code-execution-vulnerability-what-you-need-to-know/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b6c0973");
  script_set_attribute(attribute:"see_also", value:"https://backstage.forgerock.com/knowledge/kb/article/a47894244");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ForgeRock Access Management version 7.0 or later, or apply a workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35464");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ForgeRock / OpenAM Jato Java Deserialization');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:forgerock:access_management");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:forgerock:openam");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("forgerock_access_management_web_detect.nbin");
  script_require_keys("installed_sw/ForgeRock Access Management");
  script_require_ports("Services/www", 80, 443, 8080, 8443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

# Note, there are workarounds per https://www.rapid7.com/blog/post/2021/06/30/forgerock-openam-pre-auth-remote-code-execution-vulnerability-what-you-need-to-know/
# We can't check for them, but for high profile vulns, we typically avoid using paranoia at least at first release.
var app = 'ForgeRock Access Management';
var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, webapp:TRUE, port:port);

var constraints = [
  {'min_version' :  '0.0', 'fixed_version' : '6.1',  'fixed_display' : '7.0' },
  {'min_version' :  '6.5', 'max_version' : '6.5.3',  'fixed_display' : '7.0' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
