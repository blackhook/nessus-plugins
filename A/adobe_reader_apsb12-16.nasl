#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61562);
  script_version("1.9");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id(
    "CVE-2012-1525",
    "CVE-2012-2049",
    "CVE-2012-2050",
    "CVE-2012-2051",
    "CVE-2012-4147",
    "CVE-2012-4148",
    "CVE-2012-4149",
    "CVE-2012-4150",
    "CVE-2012-4151",
    "CVE-2012-4152",
    "CVE-2012-4153",
    "CVE-2012-4154",
    "CVE-2012-4155",
    "CVE-2012-4156",
    "CVE-2012-4157",
    "CVE-2012-4158",
    "CVE-2012-4159",
    "CVE-2012-4160"
  );
  script_bugtraq_id(
    55005,
    55006,
    55007,
    55008,
    55010,
    55011,
    55012,
    55013,
    55015,
    55016,
    55017,
    55018,
    55019,
    55020,
    55024,
    55026,
    55027
  );

  script_name(english:"Adobe Reader < 10.1.4 / 9.5.2 Multiple Vulnerabilities (APSB12-16)");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is earlier
than 10.1.4 / 9.5.2 and is, therefore, affected by multiple
vulnerabilities :

  - An unspecified stack-based buffer overflow error
    exists. (CVE-2012-2049)

  - An unspecified buffer overflow error exists.
    (CVE-2012-2050)

  - Numerous unspecified memory corruption errors exist.
    (CVE-2012-2051, CVE-2012-4147, CVE-2012-4148,
    CVE-2012-4149, CVE-2012-4150, CVE-2012-4151,
    CVE-2012-4152, CVE-2012-4153, CVE-2012-4154,
    CVE-2012-4155, CVE-2012-4156, CVE-2012-4157,
    CVE-2012-4158, CVE-2012-4159, CVE-2012-4160)

  - An unspecified heap-based buffer overflow error
    exists. (CVE-2012-1525)");
  script_set_attribute(attribute:"see_also", value:"http://telussecuritylabs.com/threats/show/TSL20120814-01");
  script_set_attribute(attribute:"see_also", value:"http://j00ru.vexillium.org/?p=1175");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-16.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 10.1.4 / 9.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4160");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');

info =  '';
info2 = '';
vuln = 0;
vers = get_kb_list('SMB/Acroread/Version');
if (isnull(vers)) audit(AUDIT_KB_MISSING, 'SMB/Acroread/Version');

foreach version (vers)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  path = get_kb_item('SMB/Acroread/'+version+'/Path');
  if (isnull(path)) path = 'n/a';

  verui = get_kb_item('SMB/Acroread/'+version+'/Version_UI');
  if (isnull(verui)) verui = version;

  if ( 
    (ver[0] == 9 && ver[1]  < 5) ||
    (ver[0] == 9 && ver[1] == 5 && ver[2] < 2) ||
    (ver[0] == 10 && ver[1] < 1) ||
    (ver[0] == 10 && ver[1] == 1 && ver[2] < 4)
  )
  {
    vuln++;
    info += '\n  Path              : '+path+
            '\n  Installed version : '+verui+
            '\n  Fixed version     : 10.1.4 / 9.5.2\n';
  }
  else
    info2 += " and " + verui;
}

if (info)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Adobe Reader are";
    else s = " of Adobe Reader is";

    report =
      '\nThe following vulnerable instance'+s+' installed on the'+
      '\nremote host :\n'+
      info;
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}

if (info2) 
{
  info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  exit(0, "The host is not affected since Adobe Reader "+info2+" "+be+" installed.");
}
else exit(1, "Unexpected error - 'info2' is empty.");
