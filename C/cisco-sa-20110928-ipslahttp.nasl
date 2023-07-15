#TRUSTED 497562ac0d50ff624e1adedbc7335e710cab47f99a70b758888f5b59832f39818bef23d4ef6e5ea402f9472d0b7be25536084de985924071d69aed95ab0b4daaa4da558bb32530a5a2507c0af8c2888f12a6329c35c3ef619780b3a5c1305d6d698d0f22ddcfdd40ffb256125119656c824d438e58599b14247d8514f8dcf9bbc79d33a809fe7bdc7775371df970356d50718b7743efe82a738192b8bb90eed26c83faae4959f553faa82b04ffe99ea2b323e25f31fb2509f75fd076ebc2f1a986c2befdb416cb4a3a0be0bcef5e8fc78ea1747db733178ebe70f2b92f10a6e22bfc549ed6937f3b32740860366110f8876beb2a5a97cfcf856f37d5c973d8d00c28ba4fe8fb99b7781f60a376f1e8cccb8db798df1a37e02e27391204b6db16638c15268840d492edaaae869e8a5e56e718843b1974c55327ae23ec903f7ff799179656832718310a09cd1564e850fa46f64860d83e4715cd2af5ed807186180c536410d89fbd125275890562994d4596c6383480f168166b3536561eddfcd503b0339d91251719199b8166fb10bc6e3e0bb2e1a0cc5195cb2f49680fc8cca612d54a3d926836afa9723bd321bcb414ac72e935a3ef2004d46b2649ec35ed30b06bfe7dad7aa0392de5d388c811dc3407329663de7a43481210d1991c2a0f39f07b914c94724fa2e3d4225777fba76fdcb5b300913a92590106cef29e4fb62e
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20110928-ipsla.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(56315);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2011-3272");
  script_bugtraq_id(49823);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtk67073");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110928-ipsla");

  script_name(english:"Cisco IOS Software IP Service Level Agreement Vulnerability (cisco-sa-20110928-ipsla)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS IP Service Level Agreement (IP SLA) feature contains a
denial of service (DoS) vulnerability. The vulnerability is triggered
when malformed UDP packets are sent to a vulnerable device. The
vulnerable UDP port numbers depend on the device configuration.
Default ports are not used for the vulnerable UDP IP SLA operation or
for the UDP responder ports. Cisco has released free software updates
that address this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110928-ipsla
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94afcda9"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110928-ipsla."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");
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
if ( version == '15.1(1)S' ) flag++;
if ( version == '15.1(1)S1' ) flag++;
if ( version == '15.1(1)S2' ) flag++;
if ( version == '15.1(1)SA1' ) flag++;
if ( version == '15.1(1)SA2' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sla_responder", "show ip sla responder");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Enable", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sla_configuration", "show ip sla configuration");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"operation[^\r\n]*udp-echo", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"operation[^\r\n]*udp-jitter", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
