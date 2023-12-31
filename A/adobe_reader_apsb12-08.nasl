#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58683);
  script_version("1.10");
  script_cvs_date("Date: 2018/06/27 18:42:27");

  script_cve_id("CVE-2012-0774", "CVE-2012-0775", "CVE-2012-0776");
  script_bugtraq_id(52949, 52951, 52952);

  script_name(english:"Adobe Reader < 10.1.3 / 9.5.1 Multiple Vulnerabilities (APSB12-08)");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis",value:
"The version of Adobe Reader on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Reader installed on the remote host is earlier
than 10.1.3 / 9.5.1 and is, therefore, affected by multiple
vulnerabilities :

  - An integer overflow vulnerability exists in True Type 
    Font (TFF). (CVE-2012-0774)

  - A memory corruption vulnerability exists in the 
    JavaScript handling. (CVE-2012-0775)

  - A security bypass exists in the Adobe Reader installer.
    (CVE-2012-0776)");
  script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-12-03");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-08.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Reader 9.5.1 / 10.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies('adobe_reader_installed.nasl');
  script_require_keys('SMB/Acroread/Version');
  exit(0);
}


include('global_settings.inc');

info =  '';
info2 = '';
vuln = 0;
vers = get_kb_list('SMB/Acroread/Version');
if (isnull(vers)) exit(0, 'The "SMB/Acroread/Version" KB list is missing.');

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
    (ver[0] == 9 && ver[1] == 5 && ver[2] == 0) ||
    (ver[0] == 10 && ver[1] < 1) ||
    (ver[0] == 10 && ver[1] == 1 && ver[2] < 3)
  )
  {
    vuln++;
    info += '\n  Path              : '+path+
            '\n  Installed version : '+verui+
            '\n  Fixed version     : 9.5.1 / 10.1.3\n';
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
