##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144104);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/14");

  script_cve_id("CVE-2020-7526");
  script_xref(name:"IAVA", value:"2020-A-0574");

  script_name(english:"PowerChute Business Edition < 9.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"An energy management tool installed on the remote Windows
host is affected by local a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"Improper Input Validation vulnerability exists in the PowerChute Business Edition tool before 
version 9.1, which could cause remote code execution when a script is executed during a shutdown event.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://www.se.com/ww/en/download/document/SEVD-2020-224-05/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e7e5cd7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PowerChute Business Edition 9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7526");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apc:powerchute");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("se_powerchute_win_installed.nbin");
  script_require_keys("installed_sw/PowerChute Business Edition", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
 
app_info = vcf::get_app_info(app:'PowerChute Business Edition');

constraints = [
  { 'fixed_version' : '9.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
