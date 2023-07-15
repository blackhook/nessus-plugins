#TRUSTED 5a6ac0742814c717bb29670bd912016efc9c6c234af3bf852279c3d1ceb355029ec72e9fc8a5d5be47b61a04bf9e314155b8681b672b7fd8c7a9eec6d46d4b1661322620461913e7aef91a167da242187f02fe9b28714ee07fc43855c7e6f32edd7424b1767248cb8257457c2356ab460b9d16f9e55beb70bab2b13570caca5ad51afbaf468a4bb74dbcdf7e31e2c2da6f849bde154047cb08e9a9d21cc80b4bb42abe70513555b8f5d65a9a0f387f45aeb7648c11a646bcb65a55236185a4177d17c77e115ffb40acf74a933ffec361ddcbb928a6212a21c5d7bd0216e80ab4cee567a3b35d6467356d9aebee315716efffd0b94a1bd578c200882acbd6200266fda217d1d1668b40393ecd36714a5ff3466899684e7e870de78d5bace454d3fb4deeb12d753cc63216006b24385a0d75129688355bfa13cc355d818e4bd9882385ae6a934e4533523367d2ed1989d2b164751d1f72203859146c43a2a90fab35657f17282e13d51d9bcff115141f876997599077b0754c174081677d812f3af5c8e18b17980f69bd56d766c8bd9565151fc6dcc0d9e1989426c4a28d92aa893af739b51b75c00e6efb86ac0a027cb20616771ac93272feafa48699d0dc1df254a13d28d6c255a811ae5fee0f73a300a8dd5f8f0e0a6eb552be70222e4142adaeab6cc5ccf76013dcc13b84b5ee48bc174ef3930bb2141eb34ecc9ea69a4426
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-cce.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70314);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-5476");
  script_bugtraq_id(62642);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx56174");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-cce");

  script_name(english:"Cisco IOS Software Zone-Based Firewall and Content Filtering Vulnerability (cisco-sa-20130925-cce)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the Zone-Based Firewall (ZBFW) component of Cisco
IOS Software could allow an unauthenticated, remote attacker to cause
an affected device to hang or reload. The vulnerability is due to
improper processing of specific HTTP packets when the device is
configured for either Cisco IOS Content Filtering or HTTP application
layer gateway (ALG) inspection. An attacker could exploit this
vulnerability by sending specific HTTP packets through an affected
device. An exploit could allow the attacker to cause an affected
device to hang or reload. Cisco has released free software updates
that address this vulnerability. Workarounds that mitigate this
vulnerability are not available."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-cce
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5586f5c3"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130925-cce."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '15.1(4)GC' ) flag++;
if ( version == '15.1(4)GC1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)M5' ) flag++;
if ( version == '15.1(4)XB6' ) flag++;
if ( version == '15.1(4)XB7' ) flag++;
if ( version == '15.1(4)XB8a' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(1)T2' ) flag++;
if ( version == '15.2(1)T3' ) flag++;
if ( version == '15.2(1)T3a' ) flag++;
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(2)T' ) flag++;
if ( version == '15.2(2)T1' ) flag++;
if ( version == '15.2(2)T2' ) flag++;
if ( version == '15.2(2)T3' ) flag++;
if ( version == '15.2(2)T4' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GC1' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)T2' ) flag++;
if ( version == '15.2(3)T3' ) flag++;
if ( version == '15.2(3)XA' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"service-policy (urlfilter|http) .*", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map_type_inspect_zone-pair_urlfilter", "show policy-map type inspect zone-pair urlfilter");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"URL Filtering is in", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
