#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@


include("compat.inc");

if(description)
{
 script_id(22481);
 script_version ("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVB", value:"0001-B-0525");

 script_name(english:"Do not scan fragile devices");

 script_set_attribute(attribute:"synopsis", value:
"This script offers a way to control scanning of fragile devices." );
 script_set_attribute(attribute:"description", value:
"This script offers a way to control scanning of certain categories of
network devices and hosts that are considered 'fragile' and might
crash if probed." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/02");
 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_family(english:"Settings");
 script_summary(english:"Define which type of hosts can or can not be scanned");
 script_copyright(english:"This script is Copyright (C) 2006-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_category(ACT_INIT);

 script_add_preference(name:"Scan Network Printers", type:"checkbox", value:"no");
 script_add_preference(name:"Scan Novell Netware hosts", type:"checkbox", value:"no");
 script_add_preference(name:"Scan Operational Technology devices", type:"checkbox", value:"yes");
 exit(0);
}

include("data_protection.inc");

function dont_scan_settings_network_printers( opt )
{
 # if opt "yes" then scan printers
 # if opt not "yes" / "no" then dont scan printers
 # if opt null and unsafe checks then scan printers
 if ( opt )
 {
  if ( "yes" >< opt )
  {
   # opt "yes" then scan printers
   set_kb_item(name:"Scan/Do_Scan_Printers", value:TRUE);
  }
  # else opt is not yes, dont scan printers
 }
 else if ( safe_checks() == 0 )
 {
  # opt null and unsafe checks then scan printers
  set_kb_item(name:"Scan/Do_Scan_Printers", value:TRUE);
 }
}


function dont_scan_settings_novell( opt )
{
 # if opt "yes" then scan novell
 # if opt not "yes" / "no" then dont scan novell
 # if opt null and unsafe checks then scan novell
 if ( opt )
 {
  if ( "yes" >< opt )
  {
   # opt "yes" then scan novell
   set_kb_item(name:"Scan/Do_Scan_Novell", value:TRUE);
  }
  # else opt is not yes, dont scan novell
 }
 else if ( safe_checks() == 0 )
 {
  # opt null and unsafe checks then scan novell
  set_kb_item(name:"Scan/Do_Scan_Novell", value:TRUE);
 }
}

function dont_scan_settings_ot( opt )
{
 # does KB already contain OT scanning value?
 if ( isnull( get_kb_item("Scan/Do_Scan_OT") ) )
 {
  # OT scanning value not in KB, create a definitive value for OT scans
  # default no OT scanning / FALSE
  local_var do_scan_ot = FALSE;
  # script preference can change value
  # script preference set, is preference value "yes"?
  if ( "yes" >< opt )
  {
   # script preference value is "yes", enable OT scans
   do_scan_ot = TRUE;
  }
  # create a definitive value for OT scans
  set_kb_item(name:"Scan/Do_Scan_OT", value:do_scan_ot);
 }
}

##
# set the required parameters to determine if data protection 
# settings need to be enabled for GDPR
##
function dont_scan_settings_gdpr(opt)
{
  if (!isnull(opt))
  {
    set_kb_item(name:data_protection::DPKB_IPADDR, value:TRUE);
    set_kb_item(name:data_protection::DPKB_USERNAME, value:TRUE);
    set_kb_item(name:data_protection::DPKB_PHONENUMBER, value:TRUE);
    set_kb_item(name:data_protection::DPKB_ENABLED, value:TRUE);
  }
}

# Perform all actions of this module from function scope
function dont_scan_settings(
 pref_scan_network_printers,
 pref_scan_novell_netware_hosts,
 pref_scan_operational_technology_devices,
 pref_scan_gdpr_dataprotection )
{
 set_kb_item(name:"/tmp/settings", value:TRUE);
 dont_scan_settings_network_printers( opt:pref_scan_network_printers );
 dont_scan_settings_novell( opt:pref_scan_novell_netware_hosts );
 dont_scan_settings_ot( opt:pref_scan_operational_technology_devices );
 dont_scan_settings_gdpr(opt:pref_scan_gdpr_dataprotection);
}

# perform required actions off this module
dont_scan_settings(
 pref_scan_network_printers:script_get_preference("Scan Network Printers"),
 pref_scan_novell_netware_hosts:script_get_preference("Scan Novell Netware hosts"),
 pref_scan_operational_technology_devices:script_get_preference("Scan Operational Technology devices"),
 pref_scan_gdpr_dataprotection:get_preference("tenableio.gdpr")
 );

