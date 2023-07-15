#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103382);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-8013");
  script_bugtraq_id(100846);

  script_name(english:"EMC Data Protection Advisor < 6.4.130 Hardcoded Password Vulnerability");
  script_summary(english:"Checks DPA web gui version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by default credential vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the EMC Data
Protection Advisor running on the remote host is 6.3.x prior to 6.3
patch 67 or 6.4.x prior to 6.4 patch 130. It is, therefore, affected
by a default credential vulnerability due to hardcoded passwords with
the Apollo System Test, emc.dpa.agent.logon and emc.dpa.metrics.logon
accounts. A remote attacker using the REST API and with knowledge
of the default password, could potentially gain administrative
privileges.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2017/Sep/36");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Data Protection Advisor version 6.3 patch 67 /
6.4 patch 130, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8013");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:data_protection_advisor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_dpa_web_detect.nasl");
  script_require_keys("installed_sw/emc_dpa");
  script_require_ports("Services/www", 80, 443, 9002);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "emc_dpa";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9002);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "6.3", "fixed_version" : "6.3.67" },
  { "min_version" : "6.4", "fixed_version" : "6.4.130" },
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
