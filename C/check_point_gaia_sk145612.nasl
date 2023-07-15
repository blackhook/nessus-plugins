#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128283);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/28  8:38:04");

  script_name(english:"Check Point Gaia Operating System Open Interfaces With Default Password (sk145612)");
  script_summary(english:"Checks the version of Gaia OS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Gaia Operating System that is vulnerable to attacks after a CPUSE clean
install and before completing the First Time Wizard. This is due to the administrator password being reset during the
CPUSE clean installation process without also resetting interface configurations.

As a result, after a CPUSE clean install and before completing the First Time Wizard, the default password may be used
to connect on all publicly available interfaces on versions R80.10 Take 479, R80.20 and R80.20.M2. On R77.30, if the
management interface is publicly available, it is open for connection via the default password.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number. Nessus has not checked whether the admin password was set and/or the First Time Wizard was completed following
a CPUSE clean install with an affected CPUSE package.");

  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk145612&src=securityAlerts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e5ad950");
  script_set_attribute(attribute:"solution", value:
"See the vendor advisory for workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of effect of the vulnerability.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:check_point:gaia_os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("check_point_gaia_os_version.nbin");
  script_require_keys("Host/Check_Point/version", "Host/Check_Point/build", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'Gaia Operating System';
version  = get_kb_item_or_exit('Host/Check_Point/version');
build    = get_kb_item('Host/Check_Point/build');
hfs      = get_kb_item('Host/Check_Point/installed_hotfixes');

if ((version != 'R77.30' && !(version == 'R80.10' && build == '479') && version != 'R80.20' && version != 'R80.20.M2')
     || 'sk145612' >< hfs)
  audit(AUDIT_DEVICE_NOT_VULN, 'The remote device running ' + app_name + ' (version ' + version + ')');

report =
  '\n  Installed version      : ' + version +
  '\n  Build                  : ' + build +
  '\n  Hotfix required        : Hotfix sk145612';
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
