#TRUSTED 31fedb98d1ced7131d5a0906d45d7c4bd90879407a922a9a7841b8158d3b333416a98ef7c698c732e6230302d702ca01503efd45706966de7e0d0d4200777a5d1d7f5cf8141659e8805aed42342e38292b5e1505bb943b931c925ff5867857b3923f1d236bdc3669fa4a108fcfc90e85ccc52eb4eaab7647fe6ae9db20bbbb8932ec6c877a62e05ab52b9b96441c867011495114689e5f6e7c7f37423a3837b7c24f1554f62046d8a6e97633cf5840b3f65bbd3e184a7f66f822ae4b9039d21d5b84f93d4607efc46543cce5d513c06c5b76859f410c03b7e0ccda40faf50acba1d2d29c0576f3a56edb76b8cc17401a352d90887b590bc904985fe45d0d9451ffa82817c6b17a0459b03a1f699e251482c46538d687c6bd3054bec86bf4786718adf44b71f71c09132e4d9bcdf18dc7172b88fd0e7a31283d1b52e61879dd567abcd9a98665ccecbf209adb9a806265c8ac7d09dd8cfb26c1b75c529e8b1420267d546c6388aa065eda8c353578c138782adc1074ca3153f662dcd9d931c3f106f98993b53af8404a6f6747bf932e9e75b3b94772d2e0aba182ffe7a16e1e5c258f444d2b7347accf3e0437dd340612d1207f1b0fc277587786b00e1494c1eb0cc25313177fb6a1d5e9fce489772c4d6863b16d9892354d13d656b51bd8435f9085c095616913ad8bc936b9ba6af956474998933ed5e157a5c94569fdd73fdc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96660);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2302");
  script_bugtraq_id(95394);
  script_xref(name:"JSA", value:"JSA10771");

  script_name(english:"Juniper Junos rpd BGP add-path DoS (JSA10771)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the routing process daemon (rpd) due to improper
handling of BGP packets. An unauthenticated, remote attacker can
exploit this issue, by sending specially crafted BGP packets, to
cause the rdp daemon to crash and restart.

Note that this vulnerability only affects devices configured with the
BGP add-path feature enabled with the 'send' option or with both the
'send' and 'receive' options.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version and current configuration.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10771");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10771.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['12.1X46'] = '12.1X46-D55';
fixes['12.1X47'] = '12.1X47-D45';
fixes['12.3']    = '12.3R13';
fixes['12.3X48'] = '12.3X48-D35';
fixes['13.3']    = '13.3R10';
fixes['14.1']    = '14.1R8';
fixes['14.1X53'] = '14.1X53-D40';
fixes['14.1X55'] = '14.1X55-D35';
fixes['14.2']    = '14.2R6';
fixes['15.1F']   = '15.1F2';
fixes['15.1X49'] = '15.1X49-D20';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  lines = split(buf, sep:'\n', keep:FALSE);
 
  # Parse BGP groups that have 'add-path' feature is enabled with 'send' option 
  pattern = "^set.* protocols bgp group (\S+) .* add-path.* send";
  groups  = make_list();   

  foreach line (lines)
  {
    matches = pregmatch(string:line, pattern:pattern);
    if (matches)
    {
      if (junos_check_config(buf:buf, pattern:matches[0]))
        groups = make_list(groups, matches[1]);
    }
  }
  if (empty(groups))
    audit(AUDIT_HOST_NOT, "affected because the BGP 'add-path' feature is not enabled with the 'send' option");

  # Parse local_address from parsed BGP group
  local_addresses = make_list();
  foreach line (lines)
  {
    foreach group (list_uniq(groups)) 
    {
      pattern = "^set.* protocols bgp group " + group + " local-address (\S+)"; 
      if (junos_check_config(buf:buf, pattern:pattern))
      {
        matches = pregmatch(string:line, pattern:pattern);
        if (matches)
          local_addresses = make_list(local_addresses, matches[1]);
      }  
    }
  }
  if (empty(local_addresses))
    audit(AUDIT_HOST_NOT, "affected because no interface with BGP has the 'add-path' feature with the 'send' option enabled");

  # Check if parsed interfaces have the vulnerable BGP configuration
  foreach local_address (list_uniq(local_addresses))
  {
    pattern = "^set interfaces .* address " + local_address;
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    }
  }
  if (override)
    audit(AUDIT_HOST_NOT, "affected because no interface with BGP has the 'add-path' feature with the 'send' option enabled");
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
