#TRUSTED 53d2ee77d26f47ad6d63aeea1b785f4ad923db18bcad76abb01e3cbb942d1e39000d8eba16ffa5104aacab621c312c6ecdf156aa0dd42a74aab66b6accecc7847293dd7ed47d737461aefb4281bd018b82844bb7581a9ec9f97be0783ce9aede3f2bd428e7149b13989e48ae63863a5ebbf37018f289465f9c67a2b207dd412212293ad2b5e6e5663a5ae46f59adcab204e6b9f3eb375a5fd8a8741118d51471a08e1a14024cc6f41d771cb6af3adaf613af47fd8b0bc53b1281ec7037f672a36e08197413c5da7905ac839fc1ea4db0164e27283430703ede1c213334e7ee833adabcbd07c7c28887aa721cfdcbb67deb70b8b39ff16f129e055d674fc85711d65819536c59367e196ceef13d3bcec69ded93c7eb312dff738897d9fc0420fce7294d197fdfdc5235989917029fd9a8342693659410bd273fa3531439eff0887c8922f4441d9528f854e5729a0337d136a0723ff553044c022d25b4ad6c8f8b75754120c7cd3b48588527a605a40fc361ab5420da9a7248cb79ee35b989c0ceecf09235d748aa0c862905408ef4c4a8e1bfc9f9873d22e2ccbab1304efc6c5e3f15554cd16866074d8df411ad3f9123b50d2253163cac71139bd09675a2f903b333cef7fbbd3bd4add95154dccd939abf19774a4075c80a4f71cbd2de1a9cd1debaa44c45180e3f576eda726d0df8a6b4bb28fce3967318d719dc5ef019477a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85224);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-6447");
  script_bugtraq_id(75717);
  script_xref(name:"JSA", value:"JSA10682");

  script_name(english:"Juniper Junos J-Web Multiple Vulnerabilities (JSA10682)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by multiple vulnerabilities in the J-Web
component :

  - A cross-site scripting vulnerability exists due to a
    failure to validate input before returning it to users.
    A remote attacker, using a crafted request, can exploit
    this to gain access to session credentials or execute
    administrative actions through the user's browser.

  - A denial of service vulnerability exists in error
    handling that allows an attacker to crash the J-Web
    service.

Note that these issues only affects devices with J-Web enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10682");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10682.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['12.1X44'] = '12.1X44-D45';
fixes['12.1X46'] = '12.1X46-D30';
fixes['12.1X47'] = '12.1X47-D20';
fixes['12.3'] = '12.3R8';
fixes['12.3X48'] = '12.3X48-D10';
fixes['13.1'] = '13.1R5';
fixes['13.2'] = '13.2R6';
fixes['13.3'] = '13.3R4';
fixes['14.1'] = '14.1R3';
fixes['14.1X53'] = '14.1X53-D10';
fixes['14.2'] = '14.2R1';
fixes['15.1'] = '15.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for J-Web
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management http(s)? interface";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because J-Web is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE, xss:TRUE);
