#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18117);
  script_version("1.20");

  script_cve_id("CVE-2005-1166");
  script_bugtraq_id(13200);

  name["english"] = "DameWare NT Utilities Authentication Credentials Persistence Weakness";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by an
information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the copy of DameWare NT Utilities
installed on the remote host allows a local user to recover
authentication credentials because it stores sensitive information
such as username, password, remote user, and remote hostname in memory
as plaintext." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2005/Apr/227" );
   # http://web.archive.org/web/20061017191408/http://www.dameware.com/support/security/bulletin.asp?ID=SB5
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e889aa42" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to DameWare NT Utilities 3.80 / 4.9 or later." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/05");
 script_cvs_date("Date: 2018/11/15 20:50:26");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:dameware_development:dameware_nt_utilities");
script_end_attributes();

 
  summary["english"] = "Checks for authentication credentials persistence weakness in DameWare NT Utilities";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'DameWare NT Utilities';
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

version = NULL;
installed = FALSE;

if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (!isnull(prod) && "dameware nt utilities" >< tolower(prod))
    {
      version_reg = name - "/DisplayName" + "/DisplayVersion";
      version = get_kb_item(version_reg);
      installed = TRUE;
      break;
    }
  }
}

if (!installed) audit(AUDIT_NOT_INST, appname);

if (!isnull(version))
{
  if (version =~ "^([0-2]|3\.([0-9]|[0-7][0-9])|4\.([0-8]))([^0-9]|$)")
  {
    port = get_kb_item("SMB/transport");
    if (isnull(port)) port = 445;

    if (report_verbosity > 0)
    {
      report =
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.80 / 4.9\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
  else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
}
else audit(AUDIT_UNKNOWN_APP_VER, appname);
