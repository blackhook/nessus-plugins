#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141214);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-10068");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Kentico CMS 9.x / 10.x < 10.0.52 / 11.x < 11.0.48 / 12.x < 12.0.15 RCE");

  script_set_attribute(attribute:"synopsis", value:
"A web content management system on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Kentico CMS on the remote host is 9.x, 10.x prior to
10.0.52, 11.x prior to 11.0.48, or 12.x prior to 12.0.15. It is, therefore, affected by a remote code execution
vulnerability. Due to a failure to validate security headers, it is possible for a specially crafted request to the
staging service to bypass the initial authentication and proceed to deserialize user-controlled .NET object input. This
deserialization then can be used to execute arbitrary code on the server where the Kentico instance is hosted.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  # https://packetstormsecurity.com/files/157588/Kentico-CMS-12.0.14-Remote-Command-Execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c68b9e0a");
  script_set_attribute(attribute:"see_also", value:"https://devnet.kentico.com/download/hotfixes");
  script_set_attribute(attribute:"solution", value:
"Apply the hotfix applicable to your current version or upgrade to the latest available stable version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Kentico CMS Staging SyncServer Unserialize Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kentico:kentico_cms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kentico_cms_win_installed.nbin");
  script_require_keys("installed_sw/Kentico CMS");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Kentico CMS');

constraints = [
  { 'min_version' : '9.0', 'fixed_version' : '10.0.7039.22786', 'fixed_display' : '10.0.7039.22786 (Hotfix 10.0.52)' },
  { 'min_version' : '11.0', 'fixed_version' : '11.0.7032.18332', 'fixed_display' : '11.0.7032.18332 (Hotfix 11.0.48)'},
  { 'min_version' : '12.0', 'fixed_version' : '12.0.7020.30680', 'fixed_display' : '12.0.7020.30680 (Hotfix 12.0.15)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
