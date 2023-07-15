#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152046);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2021-22928");
  script_xref(name:"IAVA", value:"2021-A-0325-S");

  script_name(english:"Citrix Virtual Apps and Desktops Privilege Escalation Vulnerability (CTX319750)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Virtual Apps and Desktops installed on the remote Windows host is 2016 and earlier, or
s 1912 LTSR CU3
or earlier. It is, therefore, affected by a privilege escalation vulnerability. An unspecified flaw exists related to
Citrix Profile Management or Citrix Profile Management WMI Plugin that allows a local attacker to escalate privileges to SYSTEM.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX319750");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22928");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:virtual_apps_and_desktops");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_virtual_apps_and_desktops_installed.nbin");
  script_require_keys("installed_sw/Citrix Virtual Apps and Desktops");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Citrix Virtual Apps and Desktops', win_local:TRUE);
var dv = app_info['display_version'];
var cu = app_info['CU'];
var constraints;

if ('LTSR' >< dv)	
{
  if (empty_or_null(cu) || cu == 0 || cu < 3)
    constraints = [{ 'min_version' : '7.1912', 'max_version':'7.1912', 'fixed_display' : 'See Solution.' }];
  else if (cu == 3)
  {
    if (report_paranoia < 2)
      audit(AUDIT_PARANOID);
    else
      constraints = [{ 'min_version' : '7.1912', 'max_version':'7.1912', 'fixed_display' : 'See Solution.' }];
  }
  else
    audit(AUDIT_HOST_NOT, "affected");
}
else
{
  if (report_paranoia < 2)   
    constraints = [{ 'min_version' : '0.0', 'max_version':'7.2015', 'fixed_display' : 'See Solution.' }];
  else
    constraints = [{ 'min_version' : '0.0', 'max_version':'7.2016', 'fixed_display' : 'See Solution.' }];
}
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
