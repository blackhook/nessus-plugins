#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100595);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/15 20:50:17");


  script_name(english:"Alt-N MDaemon Remote Administration 13.0.x < 13.0.8 RCE (MD041917) (EASYBEE)");
  script_summary(english:"Checks version of MDaemon WebAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the MDaemon Remote
Administration (formerly WebAdmin) application running on the remote
web server is affected by a remote code execution vulnerability. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request or payload, to potentially execute arbitrary code.

EASYBEE is one of multiple Equation Group vulnerabilities and exploits
disclosed on 2017/04/14 by a group known as the Shadow Brokers.");
  script_set_attribute(attribute:"see_also", value:"https://www.altn.com/Support/SecurityUpdate/MD051518_MDaemon_EN/");
  # https://github.com/x0rz/EQGRP_Lost_in_Translation/tree/master/windows/exploits
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f11f213");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MDaemon version 13.5 or later. Alternatively, apply the
vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:altn:mdaemon");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:altn:mdaemon_remote_administration");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:altn:mdaemon_webconfig");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("mdaemon_webadmin_detect.nbin");
  script_require_ports("installed_sw/MDaemon WebAdmin");

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = 'MDaemon WebAdmin';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:1000);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

# Patch can only be applied to 13.0.8
if (app_info.version == "13.0.8" && report_paranoia < 2)
  audit(AUDIT_PARANOID);

vcf::check_granularity(app_info:app_info, sig_segments:2);
constraints = [{"min_version" : "13.0", "fixed_version" : "13.0.8"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
