##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164089);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2022-34235");
  script_xref(name:"IAVA", value:"2022-A-0322");

  script_name(english:"Adobe Premiere Elements Privilege Escalation (APSB22-43)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Adobe Premiere Elements installed on the remote host is prior to 2022 build 20.0 
(20220702.Git.main.e4f8578). It is, therefore, affected by the following vulnerability:

  - A privilege escalation vulnerability exists due to an uncontrolled search path element. An authenticated, local
    attacker can exploit this to escalate privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/premiere_elements/apsb22-43.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f527f74");
  script_set_attribute(attribute:"solution", value:
"Upgrade Adobe Premier Elements to build 20.0 (20220702.Git.main.e4f8578)");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_elements");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_elements_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Premiere Elements");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Premiere Elements', win_local:TRUE);

var build_timestamp = app_info['Build timestamp'];

if (empty_or_null(build_timestamp))
  audit(AUDIT_UNKNOWN_BUILD, app_info['app'], app_info['version']);

if (
  app_info.version =~ "^20\.0" &&
  ver_compare(ver:app_info['Build timestamp'], fix:'20220702', strict:FALSE) < 0
)
{
  app_info['display_version'] = app_info['version'] + ' ' + app_info['Build info'];
  vcf::report_results(app_info:app_info, fix:'build 20.0 (20220702.Git.main.e4f8578)', severity:SECURITY_WARNING);
}
else
{
  vcf::audit(app_info);
}
