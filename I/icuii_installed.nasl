#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18174);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  name["english"] = "ICUII Detection";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a video chat application." );
 script_set_attribute(attribute:"description", value:
"ICUII is installed on the remote host.  ICUII is a video chat package
for Windows that supports both 'family-oriented' and 'adult' themes." );
 script_set_attribute(attribute:"see_also", value:"http://www.icuii.com/" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this program is in accordance with your organization's
security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/02");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:cybration:icuii");
script_set_attribute(attribute:"asset_inventory", value:"True");
script_set_attribute(attribute:"agent", value:"windows");
script_end_attributes();

 
  summary["english"] = "Checks for ICUII";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for evidence of ICUII.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/ICUII/DisplayName";
if (get_kb_item(key)) security_note(get_kb_item("SMB/transport"));
