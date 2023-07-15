#TRUSTED 14662e79dd08638023a23312e6abb366bae54655569ae54ef0ec59716b68fc7626cbf0d8c0ad34786d8db1cfee6dc187f77916c27998a49080ace2bcc67307606b5cb0485728a38ce75ca59cd59bc193013d10dcfc6a37718f389e9c8150e6d89285b0bf646f45ad2a860c094c0bf2cda2086f2050c019b18014f94f8048ed72d163a05eddfde2092e62f3f7125da5d5006ccced941597e8682c8fe6007f52070e6cf45abae6687a42ef39c087b60ad37139983f0c271d34bee4d32dbb9ae753d3e4e191605d878119469653e0cf5c7afc9b925132e4527c945d8af4fc2d1ca638b6edeb1584bc7b2e389ad19683113fd463153d4969dba80b141c7cab84076dd9b2a050eeaa20444ce2be013aeb5cb146f208c7d58fdf74a02a423407032ddf6f7fa595a6c27647b070b1671e68b8137ceca4f7acbf86a6f19236fdb735202d3c01a1c4a489a6080a46af8397f181a6aaea8735bd66530578f7311f8e68cb002732e60c44b7b6bc96da7c7cc68d0a6f468935310dc05edaac9c5da4bd52ba94fa0fce38b94fa29de8902677a8b2e2411cf5f6bfde9ac3d7d4b58a450123cfb070fe377ff4b325bf2da4f92a3e2e1074f4c467dbb6f608a281ed23d9ab8ea7796200380758ec1a1c72c65938a04a44d4dabcbc3dfbd3ebb5680074ce77257d27e3e2192de0a5fb60c71e8b0e4c0ee08471f18706848466682050f77efdfffedf
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131327);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2017-12226");
  script_bugtraq_id(101063);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd73746");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-ngwc");

  script_name(english:"Cisco IOS XE Software, Catalyst, and NGWC GUI Privilege Escalation (cisco-sa-20170927-ngwc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a privilege escalation vulnerability in
the web-based Wireless Controller GUI for Cisco 5760 Wireless LAN Controllers, Cisco Catalyst 4500E Supervisor Engine
8-E (Wireless) Switches, and Cisco New Generation Wireless Controllers (NGWC) 3850. This is due to incomplete input
validation of HTTP requests by the affected GUI, if the GUI connection state or protocol changes. An authenticated,
remote attacker can exploit this by authenticating with the Wireless Controller GUI as a Lobby Administrator user of an
affected device and then changing the state or protocol for their connection to the GUI. Successful exploitation of this
vulnerability would allow an attacker to elevate their privilege level to administrator to gain full control of the
affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-ngwc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28a05a9f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd73746");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvd73746.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12226");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = get_kb_item_or_exit('Host/Cisco/IOS-XE/Model');
device_model = get_kb_item("Host/Cisco/device_model");

# Affected models:
# Cisco Catalyst 4500E Supervisor Engine 8-E (Wireless) Switches
# Cisco 5760 Wireless LAN Controllers
# Cisco New Generation Wireless Controllers (NGWC) 3850
vuln = FALSE;
show_ver = get_kb_item("Host/Cisco/show_ver");
if (device_model =~ "cat" &&
    ((product_info.model =~ "([^0-9]|^)45[0-9]{2}E" && "WS-X45-SUP8-E" >< show_ver) ||
    product_info.model =~ "([^0-9]|^)38[0-9]{2}")
   )
  vuln = TRUE;
# In advisory example, 5760 has 5700 so just look for 57xx. 
# On Software Downloads page, 5760 is the only 5700 Series WLC
else if (product_info.model =~ "([^0-9]|^)57[0-9]{2} Series Wireless LAN Controller")
  vuln = TRUE;

if (!vuln)
  audit(AUDIT_HOST_NOT, "affected");

version_list = make_list(
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd73746'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
