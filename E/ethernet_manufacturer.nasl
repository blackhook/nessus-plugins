#TRUSTED 9e27be002c569173534478eecd244229b01d6a06f8ddd17bcdc54c5738d82b9d94fff3c9b121107fc1ee3a811b25dc566b2e43106519bfe853377da6bfa7ad6203b65a3217eb2aa294a3ff87c03363e18c0c25f5a129a23f78a037e48316f54b82ead96f4c4f20cc06c4a39d33b8ec37a6714bd277f90af9123fa6d3f598b64aadb897d202ced87c60396a422782defe96cea1f491900782c5613a23170dc50c81e38a2ebe80affe58feeb58cd7a7a8ee35038fda77f8fe89ad31b7fb43a244fe25cd62a1df6b4e8d0bb6ace2f4fabcb9a0d02b896d6974e3e22067b9edc92d04b285078498af107be7ca4790ad6be09a9177eccc1f1fd9f1899703d3af326a17b5222ff15536d9677c7cb02be9f1734ed08c1ff60822ae4c86a904c3d581396c0af36680f8f08e2a5f255e6cf0c0574595a14f3212da6188b656487b047421aec26eec1e62150a3aa8026fd05480c606d7c4e76b81219b53ff863d1fa283bc496839c5b1e3f164bf809651fda2d8cf9ce1254ffa265378be89461814bae091eace5fa04107e0f9c03cf24dd2d78d67d8c2ab38dda1d5403f456701822a693679439cc2e1ba992b12fa7050bd9fd941704541fa041103e009399b807e864927511e9cb1493d88cdeb990d535ba82e49eba1634860e6b504a7c912f15be498dae3e51e6618aa6e3a4ee42ad593d399cfc29713f86709ae99f83607989c643e2e1

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35716);
 script_version ("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/13");

 script_name(english:"Ethernet Card Manufacturer Detection");
 script_summary(english: "Deduce the Ethernet brand from the OUI.");

 script_set_attribute(attribute: "synopsis", value: 
"The manufacturer can be identified from the Ethernet OUI.");
 script_set_attribute(attribute: "description", value: 
"Each ethernet MAC address starts with a 24-bit Organizationally 
Unique Identifier (OUI). These OUIs are registered by IEEE.");
 script_set_attribute(attribute: "see_also", value: "https://standards.ieee.org/faqs/regauth.html");
 # https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries
 script_set_attribute(attribute: "see_also", value: "http://www.nessus.org/u?794673b4");
 script_set_attribute(attribute: "solution", value: "n/a");
 script_set_attribute(attribute: "risk_factor", value: "None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/19");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2009-2020 Tenable Network Security, Inc.");

 script_dependencies("report_hw_macs.nasl");

 exit(0);
}

ether_list = get_kb_item("Host/mac_addrs");
if (isnull(ether_list)) exit(0);

include("oui.inc");
include("mac_address_func.inc");

oui_lines = split(oui, keep: 0);
oui = NULL;	# Free memory
oui_lines = sort(oui_lines);	# Prepare for binary search
report = '';

foreach ether (split(ether_list, keep:FALSE))
{
 if ( ether == "00:00:00:00:00:00" ) continue;
  e = ereg_replace(string: ether, pattern: "^(..):(..):(..):.*", replace: "\1\2\3 ");
  e = toupper(e);
  line = my_bsearch(v: oui_lines, e: e);
  if (line)
  {
    maker = chomp(substr(line, 7));
    report = strcat(report, ether, ' : ', maker, '\n');
    kbname = "Host/ethernet_manufacturer/macs/" + ether;
    set_kb_item(name: kbname, value: maker);
    replace_kb_item(name: "Host/ethernet_manufacturer/Enumerated", value: "TRUE");
  }
}

if (report)
{
 security_note(port: 0, extra: '\nThe following card manufacturers were identified :\n\n'+report);
}
