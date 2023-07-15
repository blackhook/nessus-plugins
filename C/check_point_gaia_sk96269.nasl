#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105001);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/12/04 15:43:54 $");

  script_name(english:"Check Point Gaia Operating System Threat Emulation Email Scan Bypass (sk96269)");
  script_summary(english:"Checks the version of Gaia OS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Gaia OS which is affected by
an issue where email may bypass scanning by the Threat Emulation blade.");
  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk96269&src=securityAlerts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18416ed7");
  script_set_attribute(attribute:"solution", value:"Update to an unaffected version or apply vendor-supplied hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:check_point:gaia_os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("check_point_gaia_os_version.nbin");
  script_require_keys("Host/Check_Point/version","Host/Check_Point/installed_hotfixes");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Gaia Operating System";
version  = get_kb_item_or_exit("Host/Check_Point/version");
hfs      = get_kb_item_or_exit("Host/Check_Point/installed_hotfixes");
blades   = get_kb_item("Host/Check_Point/enabled_blades");
vuln     = FALSE;
paranoid = FALSE;

if (version != "R77")
  audit(AUDIT_DEVICE_NOT_VULN, "The remote device running " + app_name + " (version " + version + ")");

if("sk96269" >!< hfs)
  vuln = TRUE;

if (!empty_or_null(blades))
{
  if(blades !~ 'ThreatEmulation') vuln = FALSE;
}
else if(vuln && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, "Checkpoint Gaia Operating System");
else paranoid = TRUE;

if(vuln)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fix               : Hotfix sk96269' +
    '\n';
  if(paranoid)
    report += '\n  Note: It was not possible to check whether affected blades were enabled.\n';
  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_DEVICE_NOT_VULN, "The remote device running " + app_name + " (version " + version + ")");
