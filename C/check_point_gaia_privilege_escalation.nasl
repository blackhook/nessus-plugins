#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107072);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/13  8:34:10");

  script_name(english:"Check Point Gaia Operating System Privilege Escalation");
  script_summary(english:"Checks the version of Gaia OS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Gaia OS which is affected by
an issue where low privileged users authenticated to the Gaia clish shell 
may execute arbitrary code as admin / root.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-04");
  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk123197
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0bf2e20");
  script_set_attribute(attribute:"solution", value:"Update to an unaffected version or apply vendor-supplied hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");
    
  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:check_point:gaia_os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("check_point_gaia_os_version.nbin");
  script_require_keys("Host/Check_Point/version","Host/Check_Point/installed_hotfixes");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Gaia Operating System";
version  = get_kb_item_or_exit("Host/Check_Point/version");
show_ver = get_kb_item_or_exit("Host/OS/showver");
vuln     = FALSE;
paranoid = FALSE;

jumbo_report = "";

if(show_ver =~ "Check Point (Gaia)? [46][0-9]{4} R76SP\.50")
{
   jumbo_hf = get_kb_item("Host/Check_Point/jumbo_hf");
  if(isnull(jumbo_hf))
  {
    if(report_paranoia < 2)
      audit(AUDIT_POTENTIAL_VULN, "Checkpoint Gaia Operating System");
    vuln = TRUE;
    paranoid = TRUE;
  }
  else if ( ver_compare(ver:jumbo_hf, fix:"44", strict:FALSE) < 0 )
  {
    vuln = TRUE;
    jumbo_report = ' Jumbo Hotfix Accumulator take ' + jumbo_hf;
  }
}

if( version =~ "R77\.20")
{
  vuln = TRUE;
}
else if (version =~ "R77\.30")
{
  jumbo_hf = get_kb_item("Host/Check_Point/jumbo_hf");
  if(isnull(jumbo_hf))
  {
    if(report_paranoia < 2)
      audit(AUDIT_POTENTIAL_VULN, "Checkpoint Gaia Operating System");
    vuln = TRUE;
    paranoid = TRUE;
  }
  else if ( ver_compare(ver:jumbo_hf, fix:"309", strict:FALSE) < 0 )
  {
    vuln = TRUE;
    jumbo_report = ' Jumbo Hotfix Accumulator take ' + jumbo_hf;
  }
}
else if (version =~ "R80\.10")
{
  jumbo_hf = get_kb_item("Host/Check_Point/jumbo_hf");
  if(isnull(jumbo_hf))
  {
    if(report_paranoia < 2)
      audit(AUDIT_POTENTIAL_VULN, "Checkpoint Gaia Operating System");
    vuln = TRUE;
    paranoid = TRUE;
  }
  else if ( ver_compare(ver:jumbo_hf, fix:"91", strict:FALSE) < 0 )
  {
    vuln = TRUE;
    jumbo_report = ' Jumbo Hotfix Accumulator take ' + jumbo_hf;
  }
} 

if(vuln)
{
  report =
    '\n  Installed version : ' + version + jumbo_report +
    '\n  Fix               : Update to an unaffected version or apply vendor-supplied hotfix.' +
    '\n';
  if(paranoid)
  report += '\n  Note: It was not possible to check for Jumbo Hotfix Accumulator level.\n';
  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_DEVICE_NOT_VULN, "The remote device running " + app_name + " (version " + version + ")");
