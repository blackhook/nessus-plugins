#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(11922);
 script_version("1.20");

 script_bugtraq_id(9019, 9021);

 script_name(english:"Opera < 7.22 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser which is affected by multiple
issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Opera, an alternative web browser. 

The version of Opera installed on the remote host is affected by
several issues.  One may allow an attacker to drop arbitrary files
with arbitrary names on this host; another may allow an attacker to
traverse directories on the affected host. 

To exploit these flaws, an attacker would need to set up a rogue
website and lure a user of this host visit it using Opera.  He might
then be able to execute arbitrary code on this host." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/Nov/128" );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/Nov/130" );
 script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20170912024437/http://www.opera.com:80/docs/changelogs/windows/722/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 7.22 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/11/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/11/12");
 script_cvs_date("Date: 2018/11/15 20:50:28");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();

 script_summary(english:"Determines the version of Opera.exe");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("opera_installed.nasl");
 script_require_keys("SMB/Opera/Version");
 exit(0);
}

#

include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 ||
  (ver[0] == 7 && ver[1] < 22)
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
