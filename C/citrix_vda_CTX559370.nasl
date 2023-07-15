#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177345);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id("CVE-2023-24490");
  script_xref(name:"IAVA", value:"2023-A-0304");

  script_name(english:"Citrix Virtual Apps and Desktops Improper Access Control (CTX559370)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an improper access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Virtual Apps and Desktops installed on the remote Windows host is affected by an improper access
control vulnerability. Users with only access to launch VDA applications can launch an unauthorized desktop. This
vulnerability is in the Windows Virtual Delivery Agent, which is contained in Citrix Virtual Apps and Desktops.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX559370");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24490");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:virtual_apps_and_desktops");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_virtual_apps_and_desktops_installed.nbin");
  script_require_keys("installed_sw/Citrix Virtual Apps and Desktops");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Citrix Virtual Apps and Desktops', win_local:TRUE);
var dv = app_info['display_version'];
var cu = app_info['CU'];
var constraints;

if ('2203 LTSR' >< dv)
{
  if (empty_or_null(cu) || cu == 0 || cu < 3)
    constraints = [{ 'min_version' : '7.2203', 'max_version':'7.2203', 'fixed_display' : 'See Solution.' }];
  else
    audit(AUDIT_HOST_NOT, "affected");
}
else if ('1912 LTSR' >< dv)
{
  if (empty_or_null(cu) || cu == 0 || cu < 7)
    constraints = [{ 'min_version' : '7.1912', 'max_version':'7.1912', 'fixed_display' : 'See Solution.' }];
  else
    audit(AUDIT_HOST_NOT, "affected");
}
else
  constraints = [{ 'min_version' : '0.0', 'fixed_version':'7.2305', 'fixed_display' : 'See Solution.' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
