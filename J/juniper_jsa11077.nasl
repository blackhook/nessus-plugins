#TRUSTED 2ea2ef86fa768ef6332459d77dd038fb4afef4d54b79cf91472cce328c70f44c816dbb0e1c869a9782e227a019ebe9d3accbd952a9ab19344738783cee39dfa217d0433a0aa175290acad300bd8b5ee85eb3141fb3d90b593a54bbf150eef40e71525b5375f6fba1d61fbb1648ed30a01599b4dc5fd5a94ec5ff6dbcc49602875586b04d9cda824d2f3f5015fd4d0d61b51bf7b511de3f3be5560786a371a6cd71aeeac8db9cbc8a1ae6c778af27449d27b783fae2d8f6ee4a7e8ce08e22c3703b75aa5b60d97917464b36a9801ac52a18d729eab7e63b20411ab9d6d591b8feb3b793267be55a79707aae99ebc59a5793be8104d3027d207a007b253adbb7216359ffd1b018779715007389e6e3d939ead6c306f4d852785a98b4fa1b8607907c980e622d684b43886511d48bdf281ed5d8cc650e9df8c96fdc957f670451f46c17e33b29e0551897a066b479c2d815af971a9dc5a6a221c214e87d1eab5595712fb420b8ff7a595b5b802345196375cb7525d58310050085884b9a045f97a2612b704da813b888f38f55829cd97518046141e8aa720695aa8449678a625b772adcedb0d18f994dfb42018c35b590cb28d209fa86b6dbadb527adf0567e64da89e17be6d6b43c07ae27e2299136e703bfd49ad2348d24461a151ad3208f076853a4d2836e0f2aa5d6016baea26f922e8e4c53c3bdc14f4387654e892e8c3b1e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(142145);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2020-1680");
  script_xref(name:"JSA", value:"JSA11077");
  script_xref(name:"IAVA", value:"2020-A-0494-S");

  script_name(english:"Juniper Junos OS MX Series DoS (JSA11077)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to the self reported version of Junos OS on the remote device it is affected by a denial of service (DoS)
vulnerability. An unauthenticated attacker can continuously send crafted IPv6 packets through the device causing 
repetitive MS-PIC process crashes, resulting in an extended Denial of Service condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11077");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11077");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1680");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if (model =~ "^MX")
{
  fixes['15.1R'] = '15.1R7-S7';
  fixes['15.1X53'] = '15.1X53-D593';
  fixes['16.1'] = '16.1R7-S8';
  fixes['17.2'] = '17.2R3-S4';
  fixes['17.3'] = '17.3R3-S6';
  fixes['17.4'] = '17.4R2-S11';
  fixes['18.1'] = '18.1R3-S11';
  fixes['18.2'] = '18.2R3-S6';
  fixes['18.2X75'] = '18.2X75-D41';
  fixes['18.3'] = '18.3R2-S4';
  fixes['18.4'] = '18.4R2-S5';
  fixes['19.1'] = '19.1R2';
  fixes['19.2'] = '19.2R1-S5';
  fixes['19.3'] = '19.3R2';
}

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);

# If forwarding-options dhcp-relay, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "rule.*stateful-nat64";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable');
}
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);