#TRUSTED 3e6664ac88fede73b2e28767121aae0f9b468271bd8292d02e1c52b66c11863ce8c7e84a7dc343d6c13ba64ccf629f41f16004bf0e06e6bebb166cd975b264bdb9fa86efd50d6025e088a98ef4987b7161422ea589f528da49a790d9a3120bd86dc7337aa845b00ce4846f59f1b9d85b18c316be47c3f019d629739511d567eda4b906e3b58058a2d6228ac24f2a0e23de735ba60bcd15e65e4f8e3ae519ae810caaf6c2442bd17305a996ad2e80360dfba758f6f9379b7aa76c5faefd703af666647d0adab20797e4ef4cda5a13c54d811c40e03eccce9afbfa4eb0d4fc0e1b3326bfbb35acde4c64b9f26f5b80f13828ef60288ccf8e3f10c3a66f960ad5b5d9a3f9cc5c26af963e6d52959a187495da8fc6c08feafe1ab084cdb0df957ba2c261241ab92f48c9e957e447ea227b1447cae284c949657155e8637d11dac26184d76ad0ccfa16f2c60ec55736667a5fb66a92fe5b8987f381e27a03929e8f0f1abce9c71e431cdd620a2ac7c325d1f49ff434c61a33a4b84d3d6dedc0f430f4355fce30ef6b53e3cb9c7f0111e0dfbea4389d04e13e306d9b594309bb47bc97aa1734d98d6ab690e3871ade78120faea3bf62b18b2c6ea5caa5f118ae2fb3f69edfc77f0c57ff2fa7a8b76bf0bbfc65a2d405401e0693b0bed28d164b70f448a61c982b7c3258d48a8c2d2f8abbe1fd932ee569f99a1e6063232ecf90dd5d05
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080aea4c9.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49037);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2009-1168", "CVE-2009-2049");
 script_bugtraq_id(35860, 35862);
 script_name(english:"Cisco IOS Software Border Gateway Protocol 4-Byte Autonomous System Number Vulnerabilities - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Recent versions of Cisco IOS Software support RFC4893 ("BGP Support for
Four-octet AS Number Space") and contain two remote denial of service
(DoS) vulnerabilities when handling specific Border Gateway Protocol
(BGP) updates.
These vulnerabilities affect only devices running Cisco IOS Software
with support for four-octet AS number space (here after referred to as
4-byte AS number) and BGP routing configured.
The first vulnerability could cause an affected device to reload when
processing a BGP update that contains autonomous system (AS) path
segments made up of more than one thousand autonomous systems.
The second vulnerability could cause an affected device to reload when
the affected device processes a malformed BGP update that has been
crafted to trigger the issue.
Cisco has released free software updates to address these
vulnerabilities.
No workarounds are available for the first vulnerability.
A workaround is available for the second vulnerability.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc15d4f1");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080aea4c9.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?655d2446");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090729-bgp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(16);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/29");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/07/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsy86021");
 script_xref(name:"CISCO-BUG-ID", value:"CSCta33973");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090729-bgp");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2018 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(24)T1') flag++;
else if (version == '12.4(24)T') flag++;
else if (version == '12.4(24)GC1') flag++;
else if (version == '12.2(33)SXI1') flag++;
else if (version == '12.0(32)SY9') flag++;
else if (version == '12.0(32)SY8') flag++;
else if (version == '12.0(33)S3') flag++;
else if (version == '12.0(32)S13') flag++;
else if (version == '12.0(32)S12') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"router bgp ", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
