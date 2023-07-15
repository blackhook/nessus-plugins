#TRUSTED 33a12aaf2a6fd72b4abd764ce5c3565212f468e3dfe71470ff4ef7a4d3e8e17ff0eae989c07f3d16f271eb4caed4b058924cbee4bd126c74b777c69a44d3da7a5b8a3810bae0a3f9b26238ddc900659e61034d5c48e7edfa9a1af765cc89edbd9ddc9f487a500040b435077c68b43d01c22bb5aaf965435b37506aa1fe5398314957c8ce5baef41b56b787769ce50ccedda92aaf2869abbb4df038e0d2d2eeea6c4a685bebcd200d3cf5b9acca7d60373df2ea3151770ebdb7837ad7ecbd7560cbd1ad23dcf11535fa35ff840bb0d55024b74e6a1a09c393248c0c3ecf88adf310ec54c546bf5f4855926787d8f1e4119f8be7935a4c67a127ef4d7ea78004a677b6115feaacd04c02a8647ff150ed3f8523a5a469a62796b5a3292d27a8abd2d7b733cc6a4c4a85e2e030e01623dd1c05b4b06c44a9bbd1e06f2fe8e3b6998d074252fdd54fc25abd4539309e1ba2c8e7badb4503be456e2d73ea86bcdfef9be8185583148bf9269f50304d5b088451f3758ce07c0bcf99a7db8696dd8f71cfc5f67dd420b20442e85db3334a3a3e9623d9d91339fde9924d3a243a58e804fcba7566b6f2d4d6da241cbf2adb4f5ac1d70f514ea36a531bfb321adb3a78eb97dd7f34edd7a61d5006259deb93ea4cbd39c98627e1a6b88fbf4134b57a6c6fb8f8300cbeb2d4e0f21fb421f04bb1ab8d05d65c10fe88779a81c20815e2db7f59
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080899647.shtml

include("compat.inc");

if (description)
{
  script_id(71432);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2007-4285");
  script_xref(name:"CISCO-BUG-ID", value:"CSCsi74127");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20070808-IOS-IPv6-leak");

  script_name(english:"Information Leakage Using IPv6 Routing Header in Cisco IOS XR (cisco-sa-20070808-IOS-IPv6-leak)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco IOS XR contains a vulnerability when processing specially crafted
IPv6 packets with a Type 0 Routing Header present. Exploitation of
this vulnerability leads to information leakage on affected IOS and
IOS XR devices, and can also result in a crash of the affected IOS
device. Successful exploitation on an affected device running Cisco
IOS XR will not result in a crash of the device itself, but may result
in a crash of the IPv6 subsystem.

Cisco has made free software available to address this vulnerability
for affected customers. There are workarounds available to mitigate
the effects of the vulnerability.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20070808-IOS-IPv6-leak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e301f29");
  # https://www.cisco.com/en/US/products/products_security_advisory09186a0080899647.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40c21b51");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070808-IOS-IPv6-leak.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-4285");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is (C) 2013-2021 Tenable Network Security, Inc.");

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


if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + version + '\n';
}
cbi = "CSCsi74127";
fixed_ver = "";

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if (cisco_gen_ver_compare(a:version, b:"3.3.0") >= 0)
{
   if (version =~ '^3\\.3[^0-9]')
   {
     flag++;
     fixed_ver = "upgrade to 3.4.3.1 or later";
   }
   if ((version =~ '^3\\.4[^0-9]') && cisco_gen_ver_compare(a:version, b:"3.4.3.1") == -1)
   {
     flag++;
     fixed_ver = "3.4.3.1";
   }
   if ((version =~ '^3\\.5[^0-9]') && (version != "3.5.2.5") && cisco_gen_ver_compare(a:version, b:"3.5.2.6") == -1)
   {
     flag++;
     fixed_ver = "3.5.2.6";
   }
   if ((version =~ '^3\\.6[^0-9]') && (version != "3.6.0.10") && cisco_gen_ver_compare(a:version, b:"3.6.0.12") == -1)
   {
     flag++;
     fixed_ver = "3.6.0.12";
   }
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"IPv6 is enabled", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : ' + fixed_ver + '\n';

  security_hole(port:port, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
