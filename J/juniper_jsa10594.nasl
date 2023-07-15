#TRUSTED 3cb532bbca02aac17132da1699354d56eba53c04890fce1de60d5434316d948eaf09ea3f6ddbf33d2d8a2e781539b4b7e7b6040a57b429c169c95029e5e8283fbdef15e50ed60ae071fd575907a059017f689059619143e28f624d85b8ba6287f91c04c44a4e1f2e6f9c39aa5a939f34bbda43c2196165454f674e791b30d41225c2c49c8f49490d1fc056dfb1cc8d8e40bf1dd5f19d13bfdbe69b77866b972fec9dd5f950206c0dfc46ce66a08a5defc1302f1b18415652f46daf9113337bc494cdef758d895eba42986ab929d4c936a2d71a5ec1b30a9fe03af1d09b4412839b7cb8f527270fce43d3eb2142d6228e0bc448586423a125f602c01fc6aa9253d3b87ccc490c0e0785254f49c2e736312a98da67f1c0d0cc49029a70fc3fa32c72d30e0121fab57e2722d52c43bf8c1afd86384137b8810efc6b0470a0721169730d423f025f123ab5516b8a62f0bed0ef04b37b4bfe8a249ccbee5d745e98e015191a446ddc78a6447aabea13adf6bb678d090dab0fb43872e44da0081937092c8925d8e1cb1639976d1641e3d071ef64e1fa29833f5231c8640cbdf93d7fcc98844148db66cd42a0b4cdfb8c0f2da12e7daadbc1df200237ede375b16355cd0582be2c77d66aed50715a56425e3f7ba518d0e99cf16e476ce5aef2c08bdefe232b82cda6142a10aded10b623f76428bab9c0c2eedb37470edb72e092c36d47
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70479);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2013-6013");
  script_bugtraq_id(62962);
  script_xref(name:"JSA", value:"JSA10594");

  script_name(english:"Juniper Junos SRX Series flowd telnet Messages Remote Code Execution (JSA10594)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a remote code execution
vulnerability. A remote attacker can send specially crafted Telnet
messages to cause a buffer overflow the flow daemon (flowd).

Note that this issue only affects devices with telnet pass-through
authentication enabled on the device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10594");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10594.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (compare_build_dates(build_date, '2013-07-11') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '11.4R7-S2')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['10.4'] = '10.4S14';
fixes['11.4'] = '11.4R8';
fixes['12.1X44'] = '12.1X44-D15';
fixes['12.1X45'] = '12.1X45-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for firewall telnet pass-through authentication
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set access firewall-authentication pass-through telnet";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT,
      'affected because Telnet pass-through authentication is not enabled'); 
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
