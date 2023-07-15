#TRUSTED 25602f12f1402bec6c16033d71e95ca76d52ec264d158c39ac8fcd3949abd3ea9637ab66f35c5209836c6fe393eeb171013122eed2caecacf287f2c2cf6d2c376f6eb6ffee0addda4ab14591b0f86cc4bc754293bfbf5767362007476d70bbb712f8b6de2c4dd254cda766fee3676e5787d26ee3b97b2406c0c72877c25aaa9d791928371fd4c314464bf14aefe70cc8f00331f217469ad3681262e4cebf2dc93f8356f86be3b5c1aae75b2986d9540160bb26d36c66e4ad85d8de96a919bd88208d7d117a1cdb3d259fdd214f065a099346e8c60f88ddabe0ece039be098ebd3663b2d81d055d84d9797ee00d1392c56d2a91ca1bf93e72eb0fe21bdd988a6c6268b8d97f85b8b729da6de2af56d7de26f2067a7c0f711990ee981a8a7e3b1501cee3b8ab1952e330b5d659991867a6aaf3fc45026b291811dcc6d1146166831a7fe1bf6631492213d2e45f02e03fed823a63416b7a6b6279435246735a1ad6d696796b1d61f96929be337592e0be890b740a77d060d4dcef9d37d3396ba5f163163ffb367c8c7993e9888e164481a0607fbc7f3aa05859912a6b4c5e9856f2c4f780c747f2a19bc96485a86263ed56407389e54a10d8ef1c660ba64f0958ff80ec9f7710412e8b0e02ea7a887466409064edd8203e88ea3229df7f76427f40e8baf073142b5e82c8d085dee1f4cb23cc53a2d458d5a4c49bb85eb33c967d5f

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(86420);
  script_version ("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/13");

  script_name(english:"Ethernet MAC Addresses");
  script_summary(english:"Consolidates MAC address list.");

  script_set_attribute(attribute:'synopsis', value:
"This plugin gathers MAC addresses from various sources and
consolidates them into a list.");
  script_set_attribute(attribute:'description', value:
"This plugin gathers MAC addresses discovered from both remote probing
of the host (e.g. SNMP and Netbios) and from running local checks
(e.g. ifconfig). It then consolidates the MAC addresses into a single,
unique, and uniform list.");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2015-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netbios_name_get.nasl", "ssh_get_info.nasl", "snmp_ifaces.nasl", "bad_vlan.nasl", "wmi_list_interfaces.nbin", "ifconfig_mac.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("mac_address_func.inc");
include("spad_log_func.inc");
include("oui.inc");

oui_lines = split(oui, keep: 0);
oui = NULL;	# Free memory
oui_lines = sort(oui_lines);	# Prepare for binary search


all_macs = get_all_macs();
if (empty_or_null(all_macs))
  exit(0, "No MAC addresses were detected.");

##
#  Some network devices allow for 'provisioning' of additional
#  devices which are not yet present.  Provisioned devices
#  that are not yet present should not be reported.
#
#  In the case of Cisco, these provisioned devices/interfaces have placeholder
#  mac address(es) in the range 00:00:00:00:00:<something>, where
#  <something> starts at 01 and increments in hex:
#  01 to 0F, then 11-1F, then 21-2F, etc
##

check_for_provisioned_macs = FALSE;
foreach mac_addr (all_macs)
{
  if ("00:00:00:00:00:" >< mac_addr)
  {
    spad_log(message:'Suspicious mac encountered.  Checking for evidence of provisioned mac addresses.');
    check_for_provisioned_macs = TRUE;
    break;
  }
}


if (check_for_provisioned_macs)
{
  cisco_encountered = FALSE;

  foreach mac_addr (all_macs)
  {
    if ("00:00:00:00:00:" >< mac_addr) continue;

    e = ereg_replace(string: mac_addr, pattern: "^(..):(..):(..):.*", replace: "\1\2\3 ");
    e = toupper(e);
    line = my_bsearch(v: oui_lines, e: e);
    if (line)
    {
      if ("Cisco Systems, Inc" >< line)
      {
        cisco_encountered = TRUE;
      }
    }
  }

  if (cisco_encountered)
  {
    spad_log(message:'Provisioning scenario encountered');
    new_all_macs = make_list();
    foreach mac_addr (all_macs)
    {
      if ("00:00:00:00:00" >!< mac_addr)
      {
        append_element(var: new_all_macs, value:mac_addr);
      }
      else
      {
        spad_log(message:'Discarding provisioning mac ' + mac_addr + '\n');
      }      
    }
    all_macs = new_all_macs;

    if (empty_or_null(all_macs))
      exit(0, "No MAC addresses were detected.");
  }
}


report = 'The following is a consolidated list of detected MAC addresses:\n';
foreach mac_addr (all_macs)
{
  report += "  - " + mac_addr + '\n';
}

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
