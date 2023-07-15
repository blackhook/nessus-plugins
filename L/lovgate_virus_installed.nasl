#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11633);
 script_version ("1.13");
 script_cvs_date("Date: 2019/11/25");

 script_name(english:"Lovgate Virus Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a suspicious application installed." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be infected with the 'lovgate' virus
which opens a command prompt shell on this port." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?3a0a6694" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"asset_inventory", value:"True");
script_end_attributes();

 script_summary(english:"Checks for the presence of Luvgate");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Backdoors");
# script_dependencie("find_service1.nasl");
 script_require_ports(10168, 1192, 20168);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

ports = make_list(10168, 1192, 20168);
foreach port (ports)
{
 r = get_kb_banner(port: port, type:"spontaneous");
 if(r)
   {
    if("Microsoft Windows" >< r &&
       "(C) Copyright 1985-" >< r &&
       "Microsoft Corp." >< r){security_hole(port); exit(0);}
   }
}
