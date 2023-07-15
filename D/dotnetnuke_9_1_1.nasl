#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101397);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-9822");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"DNN (DotNetNuke) 5.2.0 < 9.1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of DNN Platform (formerly DotNetNuke) running on the
remote host is 5.2.0 or later but prior to 9.1.1. It is, therefore,
affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists due to
    insecure use of web cookies to identify users. An
    unauthenticated, remote attacker can exploit this, by
    impersonating a user and uploading malicious code to the
    server, to execute arbitrary code. This vulnerability
    affects all versions from 7.0.0 to 9.1.0.

  - A flaw exists due to an overly permissive HTML5 message
    posting policy when handling cross-document messaging.
    An unauthenticated, remote attacker can exploit this to
    conduct a spoofing attack or to disclose sensitive
    information. This vulnerability affects all versions
    from 8.0.0 to 9.1.0.

  - A cross-site redirection vulnerability exists due to
    improper validation of user-supplied input before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, by convincing a user to
    follow a specially crafted link, to redirect users to a
    website of the attacker's choosing. This vulnerability
    affects all versions from 7.0.0 to 9.1.0.

  - A remote code execution vulnerability exists due to a
    failure to properly validate file types and extensions
    for uploaded files before placing them in a
    user-accessible path. An authenticated, remote attacker
    can exploit this to execute arbitrary code with the
    privileges of the web service. This vulnerability
    affects all versions from 5.2.0 to 9.1.0.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.dnnsoftware.com/community-blog/cid/155437/dnn-911-security-bulletin-released
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a950f08f");
  script_set_attribute(attribute:"see_also", value:"https://www.dnnsoftware.com/community/security/security-center");
  # https://www.f5.com/labs/articles/threat-intelligence/zealot-new-apache-struts-campaign-uses-eternalblue-and-eternalsynergy-to-mine-monero-on-internal-networks
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d53b62d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DNN Platform version 9.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9822");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'DotNetNuke Cookie Deserialization Remote Code Excecution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_keys("installed_sw/DNN");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("vcf.inc");

app = "DNN";

get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80, asp:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
      {"min_version" : "5.2.0", "fixed_version" : "9.1.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
