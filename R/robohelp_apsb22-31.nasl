##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162320);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-30670");
  script_xref(name:"IAVB", value:"2022-B-0016");

  script_name(english:"Adobe RoboHelp Server < 11 Update 3 Privilege Escalation (APSB22-31)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe RoboHelp Server installed on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe RoboHelp Server installed on the remote host is affected a privilege escalation vulnerability.
An authenticated, remote attacker can exploit this to gain privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/robohelp-server/apsb22-31.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f07c6e8b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe RoboHelp Server version 11 Update 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("robohelp_server_installed.nasl");
  script_require_keys("installed_sw/Adobe RoboHelp Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Adobe RoboHelp Server');
var constraints = [{'fixed_version': '11.3', 'fixed_display': 'RHS 11 (Update 3)'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
