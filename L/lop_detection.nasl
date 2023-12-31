#
# (C) Tenable Network Security, Inc.
#
#


include("compat.inc");

if (description)
{
 script_id(12002);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

 script_name(english:"LOP.COM Detection");
 script_summary(english:"LOP.COM detection");

 script_set_attribute(attribute:"synopsis", value:"The remote host has a suspicious application installed.");
 script_set_attribute(attribute:"description", value:
"The remote host is using the LOP.COM program. You should ensure that:
- the user intended to install LOP.COM (it is sometimes silently
installed) - the use of LOP.COM matches your corporate mandates and
security policies.

To remove this sort of software, install software such as Ad-Aware or
Spybot.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f128ac9");
 script_set_attribute(attribute:"solution", value:"Uninstall this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"x-cpe:/a:lop.com/lop.com");
script_set_attribute(attribute:"asset_inventory", value:"True");
script_set_attribute(attribute:"agent", value:"windows");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows");
 script_dependencies( "smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("audit.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

path[0] = "clsid\{d44b5436-b3e4-4595-b0e9-106690e70a58}";
path[1] = "software\classes\clsid\{162ab497-087d-4fb3-83ba-4f5159613796}";
path[2] = "software\classes\clsid\{80fddae7-d472-4e1f-8c3a-36b75a091c44}";
path[3] = "software\classes\clsid\{9b35a850-66ab-4c6d-8a66-136ecadcd904}";
path[4] = "software\classes\clsid\{b9c38317-4e71-4d7b-b072-3aa8dda923b3}";
path[5] = "software\classes\clsid\{d3119527-9be0-422c-b9fa-5143d75dfbea}";
path[6] = "software\classes\clsid\{d44b5436-b3e4-4595-b0e9-106690e70a58}";
path[7] = "software\classes\clsid\{e69e6d3b-861e-4c8b-bdd4-a8b7a61af313}";
path[8] = "software\microsoft\internet explorer\toolbar\{80fddae7-d472-4e1f-8c3a-36b75a091c44}";
path[9] = "software\microsoft\internet explorer\toolbar\{9b35a850-66ab-4c6d-8a66-136ecadcd904}";
path[10] = "software\microsoft\internet explorer\toolbar\{d3119527-9be0-422c-b9fa-5143d75dfbea}";
path[11] = "software\microsoft\internet explorer\toolbar\{ec28a907-37ac-4d9a-a928-ee2ba555a141}";
path[12] ="software\microsoft\windows\currentversion\explorer\browser helper objects\{162ab497-087d-4fb3-83ba-4f5159613796}";
path[13] ="software\microsoft\windows\currentversion\explorer\browser helper objects\{4b8edc53-6cfd-4ee4-9504-38ce7a5bc416}";
path[14] ="software\microsoft\windows\currentversion\explorer\browser helper objects\{7dd896a9-7aeb-430f-955b-cd125604fdcb}";
path[15] ="software\microsoft\windows\currentversion\explorer\browser helper objects\{b9c38317-4e71-4d7b-b072-3aa8dda923b3}";
path[16] ="software\microsoft\windows\currentversion\explorer\browser helper objects\{e69e6d3b-861e-4c8b-bdd4-a8b7a61af313}";
path[17] ="software\microsoft\windows\currentversion\installer\products\c8d617f6f8933d11581e000540386890\webpublfiles\usage";
path[18] = "software\microsoft\windows\currentversion\run\twquh";
path[19] = "software\microsoft\windows\currentversion\run\winactive";
path[20] = "software\microsoft\windows\currentversion\run\wstpsh";
path[21] = "software\microsoft\windows\currentversion\run\ybmk";
path[22] = "software\microsoft\windows\currentversion\uninstall\nthlllleth";
path[23] = "software\microsoft\windows\currentversion\uninstall\shubryochuss";




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
