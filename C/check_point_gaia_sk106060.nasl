#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104999);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2015-3456");
  script_bugtraq_id(74640);

  script_name(english:"Check Point Gaia Operating System VM escape and code execution (sk106060)(VENOM)");
  script_summary(english:"Checks the version of Gaia OS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Gaia OS which is affected by
a vulnerability in the virtual floppy drive code which may allow an
attacker to escape a virtualized environment and obtain code execution
on the underlying host.");
  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk106060&src=securityAlerts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aef5405e");
  script_set_attribute(attribute:"see_also", value:"http://venom.crowdstrike.com/");
  script_set_attribute(attribute:"solution", value:
"Update to an unaffected version or apply vendor-supplied hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:check_point:gaia_os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("check_point_gaia_os_version.nbin");
  script_require_keys("Host/Check_Point/version", "Host/Check_Point/te_ver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Gaia Operating System";
version  = get_kb_item_or_exit("Host/Check_Point/version");
blades   = get_kb_item("Host/Check_Point/enabled_blades");
vuln     = FALSE;
paranoid = FALSE;

if (version !~ "R77(\.[123]0)?$")
  audit(AUDIT_DEVICE_NOT_VULN, "The remote device running " + app_name + " (version " + version + ")");
te_ver = get_kb_item_or_exit("Host/Check_Point/te_ver");

if(ver_compare(ver:te_ver, fix:"24.990000010", strict:FALSE) < 0)
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
    '\n  Installed version : Threat Emulation engine version ' + te_ver +
    '\n  Fix               : Threat Emulation engine version 24.990000010' +
    '\n';
  if(paranoid)
    report += '\n  Note: It was not possible to check whether affected blades were enabled.\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_DEVICE_NOT_VULN, "The remote device running " + app_name + " (version " + version + ")");
