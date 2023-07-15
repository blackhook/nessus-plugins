#TRUSTED 587520287e500c2cc73aeb0cf8081ac9c6af924448997548091aa4a96f486ad6006e25fbc1290dbd0bacb6e2db8c17f908ee502b37592cdf934da49f9d9a2742bcf3f116893d66bc5abe1a755279f249ac9ad00c45b044d2b3c598f2cd6d4e9822d6db9014962e3050be6f7b110d22b7b5387a74b40d7c03cc9f5cf99cddefba4c17c0d17df56ecdf4bd8f5330f9d38437080cd54de121508a8caa02a2fe1cd92dc4d566030f05a50e626a7375b218d9fa1302b59a26dc6b36fed9bdf1a749122b5554d0d07c18a33ce29cda261cf35329de3ddd0fc1cb40775ed28888f5a34d802401b29cc00d04223bff7a2c8ec7f127503d713a538012f5babbc39d275d37e21cab46acf5a6067bd95613e49e46ad63a448223f05f359811c1a52d8e86f91da705d36f5825155dba3ee84d9fbede19e8cb95ee46e5cc06a06b5229bb50beeefa4a24f33f040e383a0bebfb5004e4f864684b8f52a85b8210e2af5dd731d4f80ae16c2cb76a240bd015c026b255fe6fc5aaea3cc54b59fc24dc11051564b869d78b4ceb759a51a0dc90ce57642a6d12eb232b1c959471d1c7f6105bb74e140236b589483d72143d51a42849313391b488490f9b8208931cff27010ee678cda04a987cc2a0ec1331c4435da3ccbb5b2c2d0e8e54952a4f4aab103068114bca8677482f62f6fb9cc63753e6097adfaa4eeb46b00db4ad4b4402becb89122c2ff
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130327-ipsla.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(65887);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-1148");
  script_bugtraq_id(58739);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc72594");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130327-ipsla");

  script_name(english:"Cisco IOS Software IP Service Level Agreement Vulnerability (cisco-sa-20130327-ipsla)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS Software implementation of the IP Service Level
Agreement (IP SLA) feature contains a vulnerability in the validation
of IP SLA packets that could allow an unauthenticated, remote attacker
to cause a denial of service (DoS) condition. Cisco has released free
software updates that address this vulnerability. Mitigations for this
vulnerability are available."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130327-ipsla
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0689a717"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130327-ipsla."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

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
if ( version == '15.2(4)M' ) flag++;
if ( version == '15.2(4)M1' ) flag++;
if ( version == '15.2(4)M2' ) flag++;
if ( version == '15.2(4)S' ) flag++;
if ( version == '15.2(4)S0c' ) flag++;
if ( version == '15.2(4)S0xb' ) flag++;
if ( version == '15.2(4)S1' ) flag++;
if ( version == '15.2(4)XB10' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip sla responder", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sla_responder", "show ip sla responder");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"General[^\r\n]*Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
