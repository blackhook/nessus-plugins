#TRUSTED acd5020755927d52b658b86406459c04a9be2f7a308dbdb1d575b39347b4b48b6a7500fe7d64322bbff27d4ae7dd8d42790a185090e31c63070c66d02ed67c07f1b08b968b5550ad1e5fbfbb3ae1db31178866e63dac66082b02331b461fb4787311bbf61e83cba6a770ee59afc06f132d95f91e4efc9a1e98dad5b81d036f05aafe2f024339f8a1d78566e159221d288b528c5b3b863d0b016ba5f24129bc52846827c205184ee6d6def7498d8ecb08c30580f76d8d3a3f483beec1c5ac3d9e6c27425d5a83cd613d73214aa7efe18bd1f3e068fa3358f08dab843c2897440c1d8979ce78cc4095ab3d68630137d8f0f22464f70226ac9ea1f9066a9674049fc28ebfe369191b5168e833146a0f34deeb2b61684c935a4ac7f1c8cfc377f6ecd94971e6585ed48ef7256c964bbec7bca26183eb8b5bba82faa06df9e72a35577a20678eb6499529304e3f5c81dc1abac3f6f198953547e7136ef18aa4f97d76cf9727b5a10df05f81c886f473cda383804d2f0e74cf22d54908b450b07a7daf1d5e8d6a9768ea2389a146e29b75e5a427ddc0d65116158bc3380f250d4958e9f0f04a70adaae6aa4cc7f8379736363fd5c97ef9776b3d05b16d4532fba8e69b5f7f9ae6104993f7ab74506949d772a79693b0b4f5d251d2a3ccb9e29a92275903bcf54996ebd612f5f157b5aa2f696f6be9704334bfb90644bb5181ac9ad6c5
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20100324-ldp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(71434);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2010-0576");
  script_bugtraq_id(38938);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsj25893");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100324-ldp");

  script_name(english:"Cisco IOS XR Software Multiprotocol Label Switching Packet Vulnerability (cisco-sa-20100324-ldp)");
  script_summary(english:"Checks the IOS XR version");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A device running Cisco IOS XR Software is vulnerable to a remote denial
of service (DoS) condition if it is configured for Multiprotocol Label
Switching (MPLS) and has support for Label Distribution Protocol (LDP). 
A crafted LDP UDP packet can cause an affected device running Cisco IOS
XR Software to restart the mpls_ldp process.  A system is vulnerable if
configured with either LDP or Tag Distribution Protocol (TDP).  Cisco
has released free software updates that address this vulnerability. 
Workarounds that mitigate this vulnerability are available."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100324-ldp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d8fad9b");
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100324-ldp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0576");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report = "";
override = 0;

fixed_ver = "";
cbi = "CSCsj25893";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if (
     (cisco_gen_ver_compare(a:"3.5.0", b:version) >= 0) &&
     (cisco_gen_ver_compare(a:"3.5.2", b:version) < 0)
   ) flag ++;
fixed_ver = "3.5.2.6";

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_mpls", "show running-config mpls");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"mpls ldp", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    # Cisco IOS XR
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp_brief", "show udp brief");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:":646\s", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed Release : ' + version +
    '\n    Fixed Release     : ' + fixed_ver + '\n';

  security_hole(port:port, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
