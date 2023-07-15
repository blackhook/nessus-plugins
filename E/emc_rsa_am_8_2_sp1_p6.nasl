#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104897);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-14379");
  script_bugtraq_id(101925);

  script_name(english:"EMC RSA Authentication Manager < 8.2 SP1 Patch 6 Stored Cross-Site Scripting (ESA-2017-152)");
  script_summary(english:"Checks the version of EMC RSA Authentication Manager.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Authentication Manager running on the remote
host is prior to 8.2 SP1 Patch 6 (8.2.1.6). It is, therefore, affected
by an unspecified stored cross-site scripting vulnerability. Attackers
could potentially exploit this vulnerability to execute arbitrary HTML
or JavaScript code in the user's browser session in the context of the
affected RSA Authentication Manager application.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2017/Nov/34");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Authentication Manager version 8.2 SP1 Patch 6 
(8.2.1.6) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14379");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_authentication_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:authentication_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_rsa_am_detect.nbin");
  script_require_keys("installed_sw/EMC RSA Authentication Manager");
  script_require_ports("Services/www", 7004);

  exit(0);
}

include("http.inc");
include("vcf.inc");

port = get_http_port(default:7004);

app_info = vcf::get_app_info(app:"EMC RSA Authentication Manager", port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "fixed_version" : "8.2.1.6", "fixed_display" :"8.2 SP1 Patch 6" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{"xss":TRUE});
