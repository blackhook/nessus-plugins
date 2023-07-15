#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155127);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/19");

  script_cve_id("CVE-2021-42727");
  script_xref(name:"IAVB", value:"2021-B-0063-S");

  script_name(english:"Adobe RoboHelp Server < 2020.0.2 Arbitrary Code Execution (APSB21-87)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe RoboHelp Server installed on the remote host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe RoboHelp Server installed on the remote host is affected an arbitrary code execution 
vulnerability. An unauthenticated, remote attacker can exploit this to bypass authentication and execute 
arbitrary commands on an affected system. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/robohelp-server/apsb21-87.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a648e53b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe RoboHelp Server version 2020.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42727");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("robohelp_server_installed.nasl");
  script_require_keys("installed_sw/Adobe RoboHelp Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Adobe RoboHelp Server'); 
var constraints = [{'fixed_version': '2020.0.2', 'fixed_display': 'RHS2020.0.2'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
