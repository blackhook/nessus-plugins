
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128149);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/26 14:57:26");

  script_name(english:"Check Point Gaia Operating System Administrator password truncation (sk155172)");
  script_summary(english:"Checks the version of Gaia OS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Gaia Operating System which is affected by a vulnerability. Administrators
who set their password while firmware R77.20.85, R77.20.86 or R77.20.87 (< Build 990172921) were installed can
authenticate to the SMB appliance using only the first 8 characters. This is because administrator passwords which were
created or changed while using the affected firmware versions are enforced with a weaker password hash algorithm than
previous versions.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk155172&src=securityAlerts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc4c9338");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch and fix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of effect of the vulnerability.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:check_point:gaia_os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("check_point_gaia_os_version.nbin");
  script_require_keys("Host/Check_Point/version", "Host/Check_Point/model", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'Gaia Operating System';
version  = get_kb_item_or_exit('Host/Check_Point/version');
cpview    = get_kb_item('Host/Check_Point/cpview');
hfs      = get_kb_item('Host/Check_Point/installed_hotfixes');
model    = get_kb_item_or_exit('Host/Check_Point/model');

# Get the firmware kernel build number from the large cpview kb entry 
build_matches = pregmatch(pattern:"(\d+)\s+\|\r\n\|\s*-+\s*\|\r\n\|\s*Hardware", string:cpview);
if (!build_matches && version == 'R77.20.87')
  audit(AUDIT_UNKNOWN_BUILD, app_name);

if (model !~ '^Check Point ([79]00|1400)$')
  audit(AUDIT_DEVICE_NOT_VULN, 'The remote device running ' + app_name + ' (version ' + version + ')');

fw_kernel_build = int(build_matches[1]);

if ((version !~ '^R77.20.8[56]$' && !(version == 'R77.20.87' && fw_kernel_build < 990172921)) || 'sk155172' >< hfs)
  audit(AUDIT_DEVICE_NOT_VULN, 'The remote device running ' + app_name + ' (version ' + version + ')');

report =
  '\n  Installed version      : ' + version +
  '\n  Hotfix required        : Hotfix sk155172' +
  '\n  Note: It was not possible to check whether the administrator password was set or changed while while the
vulnerable firmware was installed.\n';
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
