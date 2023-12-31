#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12015);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

 script_name(english:"IPINSIGHT Detection");
 script_summary(english:"IPINSIGHT detection");

 script_set_attribute(attribute:"synopsis", value:"The remote host has an Internet Explorer Addon installed.");
 script_set_attribute(attribute:"description", value:
"The remote host is using the IPINSIGHT program. You should ensure that
the user intended to install IPINSIGHT as it is sometimes silently
installed.");
 script_set_attribute(attribute:"see_also", value:"http://www.spywareremove.com/removeIPInsight.html");
 script_set_attribute(attribute:"solution", value:
"Check that the use of this software matches your corporate security
policies.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ipinsight:ipinsight");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"agent", value:"windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

# start the script

if ( ! get_kb_item("SMB/Registry/Enumerated" )) exit(1);
include("smb_func.inc");
include("audit.inc");


path[0] = "software\classes\babeie.agentie";
path[1] = "software\classes\babeie.agentie.1";
path[2] = "software\classes\babeie.agentie\clsid";
path[3] = "software\classes\babeie.agentie\curver";
path[4] = "software\classes\babeie.handler\clsid";
path[5] = "software\classes\babeie.handler\curver";
path[6] = "software\classes\babeie.helper\clsid";
path[7] = "software\classes\babeie.helper\curver";
path[8] = "software\classes\bredobj.bredobj";
path[9] = "software\classes\bredobj.bredobj.1";
path[10] = "software\classes\bredobj.bredobj\curver";
path[11] = "software\classes\clsid\{000004cc-e4ff-4f2c-bc30-dbef0b983bc9}";
path[12] = "software\classes\clsid\{21ffb6c0-0da1-11d5-a9d5-00500413153c}";
path[13] = "software\classes\clsid\{2eb3eff2-f707-4ea8-81aa-4b65d2799f31}";
path[14] = "software\classes\clsid\{6656b666-992f-4d74-8588-8ca69e97d90c}";
path[15] = "software\classes\clsid\{665acd90-4541-4836-9fe4-062386bb8f05}";
path[16] = "software\classes\clsid\{9346a6bb-1ed0-4174-afb4-13cd4ec0aa40}";
path[17] = "software\classes\ezulamain.trayiconm\clsid";
path[18] = "software\classes\interface\{6e83ae1c-f69c-4aed-af98-d23c24c6fa4b}";
path[19] = "software\classes\interface\{99908473-1135-4009-be4f-32b921f86ed9}";
path[20] = "software\classes\tldctl2.urllink";
path[21] = "software\classes\tldctl2.urllink.1";
path[22] = "software\classes\typelib\{cc364a32-d59b-4e9c-9156-f0050c45005b}";
path[23] = "software\classes\winnet.update\clsid";
path[24] = "software\classes\winnet.update\curver";
path[25] = "software\ipinsight";
path[26] = "software\microsoft\windows\currentversion\app management\arpcache\ipinsight";
path[27] = "software\microsoft\windows\currentversion\explorer\browser helper objects\{000004cc-e4ff-4f2c-bc30-dbef0b983bc9}";
path[28] = "software\microsoft\windows\currentversion\run\sentry";
path[29] = "software\microsoft\windows\currentversion\uninstall\ipinsight";


port = kb_smb_transport();


login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();




if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
 NetUseDel();
 exit(0);
}


for (i=0; path[i]; i++) {
       key_h = RegOpenKey(handle:handle, key:path[i], mode:MAXIMUM_ALLOWED);
       if ( !isnull(key_h) )
       {
         RegCloseKey(handle:key_h);
         RegCloseKey(handle:handle);
	 security_warning(kb_smb_transport());
	 NetUseDel();
	 exit(0);
       }
}


RegCloseKey(handle:handle);
NetUseDel();
