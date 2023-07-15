#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34398);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-4500", "CVE-2008-4501");
  script_bugtraq_id(31556, 31563);
  script_xref(name:"EDB-ID", value:"6660");
  script_xref(name:"EDB-ID", value:"6661");
  script_xref(name:"SECUNIA", value:"32150");

  script_name(english:"Serv-U 7.x < 7.3.0.1 Multiple Remote Vulnerabilities (DoS, Traversal)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by several vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Serv-U 7.x is earlier than 7.3.0.1 and thus
is reportedly affected by the following issues :

  - An authenticated, remote attacker can cause the service
    to consume all CPU time on the remote host by 
    specifying a Windows port (eg, 'CON:') when using the 
    STOU command provided he has write access to a 
    directory.

  - An authenticated, remote attacker can overwrite or create
    arbitrary files via a directory traversal attack in the
    RNTO command.

  - An authenticated, remote attacker may be able to upload a
    file to the current Windows directory with rename by 
    placing the destination in '\' (ie, 'My Computer').");
  script_set_attribute(attribute:"see_also", value:"http://www.serv-u.com/kb/1769/ServU-7-vs-ServU-6");
  script_set_attribute(attribute:"see_also", value:"https://support.solarwinds.com/Success_Center/Serv-U_Managed_File_Transfer_Serv-U_FTP_Server/Serv-U_Documentation/release_notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U version 7.3.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2008-2022 Tenable Network Security, Inc.");

  script_dependencies("servu_version.nasl");
  script_require_keys("ftp/servu");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


port    = get_ftp_port(default:21);
version = get_kb_item_or_exit('ftp/'+port+'/servu/version');
source  = get_kb_item_or_exit('ftp/'+port+'/servu/source');

if (version !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" && version =~ "^7\.3$")
  exit(0, "The Serv-U version, "+version+" on port "+port+" is not granular enough.");

if (
  version =~ "^7\." &&
  ver_compare(ver: version , fix: '7.3.0.1', strict: FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version +
      '\n  Version source    : ' + source +
      '\n  Fixed version     : 7.3.0.1' +
      '\n';
    security_hole(port: port, extra: report);
  }
  else security_hole(port);
}
else exit(0, "The Serv-U version "+version+" install listening on port "+port+" is not affected.");
