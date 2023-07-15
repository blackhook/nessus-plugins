#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100934);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-2794");
  script_bugtraq_id(96373);
  script_xref(name:"EDB-ID", value:"39777");

  script_name(english:"DNN (DotNetNuke) < 7.4.1 Administration Authentication Bypass Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of DNN (formerly DotNetNuke) running on the remote web
server is prior to 7.4.1. It is, therefore, affected by an
authentication bypass vulnerability due to a failure to delete
installation wizard scripts post-installation. An unauthenticated,
remote attacker can exploit this, via a specially crafted request, to
create new administrator accounts and bypass authentication.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dnnsoftware.com/community/security/security-center");
  # https://www.dnnsoftware.com/community-blog/cid/155231/security-bulletins-released
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78079db0");
  # https://www.dnnsoftware.com/community-blog/cid/155198/workaround-for-potential-security-issue
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59278cb0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DNN version 7.4.1 or later. Alternatively, as a workaround,
delete the InstallWizard.aspx and InstallWizard.aspx.cs files.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_keys("installed_sw/DNN", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("vcf.inc");

app = "DNN";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
      { "max_version" : "7.4.0", "fixed_version" : "7.4.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
