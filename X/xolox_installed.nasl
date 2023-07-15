#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11431);
 script_version("1.16");

 script_name(english:"XoloX Detection");
 script_summary(english:"Determines if XoloX is installed");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote host is running P2P software."
 );
 script_set_attribute(attribute:"description",  value:
"The remote host is using XoloX, a P2P program which might not be
suitable for a business environment." );
 script_set_attribute( attribute:"solution",  value:
"Make sure that use of this software agrees with your organization's
security policy." );
 script_set_attribute(
   attribute:"risk_factor",
   value:"None"
 );
 script_set_attribute(attribute:"agent", value:"windows");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/21");
 script_cvs_date("Date: 2019/11/22");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"x-cpe:/a:xolox:xolox");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Peer-To-Peer File Sharing");
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/XoloX/DisplayName";

if (get_kb_item (key))
  security_note(get_kb_item("SMB/transport"));
