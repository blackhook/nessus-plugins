#TRUSTED 5c1f8cf4d8d01d3c14664d95838d1b5c61a8f824524e929cb51cbe0197a466acbb3561fcd09f87dd467b845ad9b6dd3a038ce6571833bf22e5bd54f8714b0f47c0d8a8810d870c023511fec11027a7d8917488b76a5785844ae66bdf8ebf7d6559726e75cb81e1e6df8f01f711d9acc6794e4a89034ff5a497f10deed5994c2b52b3e38c68c62adb4599be093594e404db9fb22da58665008822f9212d5673ce3fd79f896b46eea91bd0386d246b9c674a079312fd4135f34ae3c9660956aca5528bc080257ed3080415863fe1e93de9d1c05d99d9bd728788bd800171b4b3b2f01085c6f47676a84a828de4255d6a708bec76802c3b2d4b06e974f8ed350dff5e7047146bffa77a333a02df838dd7d0e6fc292fa5302e2291614a139daed761765054609d1e28250a29eb584036275e112f8af42fb003c072b84897f9c294e7be7cfb4074675d9b5aaba2e84c679bc75ded3ce58bd6849786d30122439e9e538c97e71821a7ffd87f5bbc05cef4e285561b554a24038b8cd5e82118219c3204f90ac7b731d6e32f0f10056a044805476a3ed83a1a326a99b25278fa2fbb738563490892edb369563719f70d1fc25fb6231ed5237ba7ac071cc1de39dacd3df00e688287d3d9d1203652545bc4460507b35a0b19e8ce2c89420a5809d99f1f424cef1820613d09c728d671a70d693073a1e9aad5e75d63be9c17a046de0b55b5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121643);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id("CVE-2019-0015");
  script_xref(name:"JSA", value:"JSA10915");

  script_name(english:"Junos OS: Deleted dynamic VPN users are allowed to establish VPN connections until reboot (JSA10915)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a vulnerability that allows deleted 
dynamic VPN users to establish dynamic VPN connections until the 
device is rebooted.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10915");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10915.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0015");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
if ( 'SRX' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['12.3X48'] = '12.3X48-D75';
fixes['15.1X49'] = '15.1X49-D150';
fixes['17.3'] = '17.3R3';
fixes['17.4'] = '17.4R2';
fixes['18.1'] = '18.1R3';
fixes['18.2'] = '18.2R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);


# If dynamic vpn isn't enabled in some form, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  override = FALSE;
  pattern = "^set vpn dyn-vpn";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have dynamic vpn enabled.');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

