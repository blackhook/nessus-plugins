#TRUSTED ad786adeabe13f9416474468e232f062d599eb3615c34dd415a723ba94566cb0a2ea74ec382bfcb958912cc10b408e43fa2b37071910b4e13d6450553c8448cdde919906a525a123826b05cd26943c0bad00ccce9777b82209ce1cc640ce5461110d9fbc22a61ec5672e5ab4875c771c885ee788710c8479634b8ac0642c33ee5944184454736ac39af361c511e4b33faca56397f5d98485018f6d889b0c053a1cd0240aac098b015ba2f23b564ed732a472fd5623ecfbb71608320ad767bceea024f7e97718239225153afa560acf038c0e37ca3c70dd1202559b0c49b79f3485a1641c077131e70fd29173061ceef0c3efd157d287dead89288d08e4db940f85f288ca8f00a8792ee581b9949ccfc3d0401c605001ae95eb467e1e494e11032ab8bfcfd69a38f4682462683dc3667e434c7272dab35af69a1093018a7084a48ceffe3eb1e93a6f5001eb87858de9d668f38b4b9b70a2349633df2f9e1ff307a58bb178a943244b1a35d0f1af401d9ab026cdbe2fd8b683216d78d13e10e5a7ef92cb7424e6beac4ba392c8260d07efbc9d1f042b57bb92aee2b3a638031e5c0c2542c719aab09605f4438ffbd38b806593c8b8141fcf0b110a1acb0e14a1bc549798b2683b87d8e6be77cdc5e41c5f4d8d3a464208d063e4cc99cf2b7796f9a2305343aeed4921af58cc44726a855946ea0490885070070208d4e8e9e88075
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61576);
  script_version("1.11");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2012-1344");
  script_bugtraq_id(54835);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtr86328");

  script_name(english:"Cisco IOS Clientless SSL VPN DoS");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS device is configured for clientless SSL VPN. It
is, therefore, affected by a denial of service vulnerability due to an 
unspecified flaw that causes a device reload when using a web browser
to refresh the SSL VPN portal page. A remote, authenticated attacker
can exploit this to cause a denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=26602");
  script_set_attribute(attribute:"solution", value:
"Contact Cisco for updated software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1344");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;

if (ver =='15.1(2)T') flag++;
if (ver =='15.1(2)EY') flag++;
if (ver =='15.1(2)EY1') flag++;
if (ver =='15.1(2)EY1a') flag++;
if (ver =='15.1(2)EY2') flag++;
if (ver =='15.1(2)EY2a') flag++;
if (ver =='15.1(2)EY3') flag++;
if (ver =='15.1(2)EY4') flag++;
if (ver =='15.1(2)GC') flag++;
if (ver =='15.1(2)GC1') flag++;
if (ver =='15.1(2)GC2') flag++;
if (ver =='15.1(4)M') flag++;
if (ver =='15.1(4)M0a') flag++;
if (ver =='15.1(4)M0b') flag++;
if (ver =='15.1(4)M1') flag++;
if (ver =='15.1(4)M2') flag++;
if (ver =='15.1(4)M3') flag++;
if (ver =='15.1(4)M3a') flag++;
if (ver =='15.1(1)MR') flag++;
if (ver =='15.1(1)MR1') flag++;
if (ver =='15.1(1)MR2') flag++;
if (ver =='15.1(1)MR3') flag++;
if (ver =='15.1(1)MR4') flag++;
if (ver =='15.1(3)MR') flag++;
if (ver =='15.1(3)MR1') flag++;
if (ver =='15.1(2)MWR') flag++;
if (ver =='15.1(1)S') flag++;
if (ver =='15.1(1)S1') flag++;
if (ver =='15.1(1)S2') flag++;
if (ver =='15.1(2)S') flag++;
if (ver =='15.1(2)S1') flag++;
if (ver =='15.1(2)S2') flag++;
if (ver =='15.1(3)S') flag++;
if (ver =='15.1(3)S0a') flag++;
if (ver =='15.1(3)S1') flag++;
if (ver =='15.1(3)S2') flag++;
if (ver =='15.1(3)S3') flag++;
if (ver =='15.1(3)S4') flag++;
if (ver =='15.1(1)SA') flag++;
if (ver =='15.1(1)SA1') flag++;
if (ver =='15.1(1)SA2') flag++;
if (ver =='15.1(1)SG') flag++;
if (ver =='15.1(1)SG1') flag++;
if (ver =='15.1(2)SG') flag++;
if (ver =='15.1(2)SNH') flag++;
if (ver =='15.1(2)SNH1') flag++;
if (ver =='15.1(2)SNI') flag++;
if (ver =='15.1(3)SVA') flag++;
if (ver =='15.1(1)SY') flag++;
if (ver =='15.1(1)SY1') flag++;
if (ver =='15.1(1)T') flag++;
if (ver =='15.1(1)T1') flag++;
if (ver =='15.1(1)T2') flag++;
if (ver =='15.1(1)T3') flag++;
if (ver =='15.1(1)T4') flag++;
if (ver =='15.1(1)T5') flag++;
if (ver =='15.1(100)T') flag++;
if (ver =='15.1(2)T0a') flag++;
if (ver =='15.1(2)T1') flag++;
if (ver =='15.1(2)T10') flag++;
if (ver =='15.1(2)T2') flag++;
if (ver =='15.1(2)T2a') flag++;
if (ver =='15.1(2)T3') flag++;
if (ver =='15.1(2)T4') flag++;
if (ver =='15.1(2)T5') flag++;
if (ver =='15.1(3)T') flag++;
if (ver =='15.1(3)T1') flag++;
if (ver =='15.1(3)T2') flag++;
if (ver =='15.1(3)T3') flag++;
if (ver =='15.1(3)T4') flag++;
if (ver =='15.1(4)T') flag++;
if (ver =='15.1(1)XB') flag++;
if (ver =='15.1(1)XB1') flag++;
if (ver =='15.1(1)XB2') flag++;
if (ver =='15.1(1)XB3') flag++;
if (ver =='15.1(4)XB4') flag++;
if (ver =='15.1(4)XB5') flag++;
if (ver =='15.1(4)XB5a') flag++;
if (ver =='15.1(4)XB6') flag++;
if (ver =='15.1(4)XB7') flag++;
if (ver =='15.1(4)XB8') flag++;
if (ver =='15.1(4)XB8a') flag++;
if (ver =='15.2(1)E') flag++;
if (ver =='15.2(1)GC') flag++;
if (ver =='15.2(1)GC1') flag++;
if (ver =='15.2(1)GC2') flag++;
if (ver =='15.2(2)GC') flag++;
if (ver =='15.2(3)GC') flag++;
if (ver =='15.2(2)JA') flag++;
if (ver =='15.2(4)M') flag++;
if (ver =='15.2(4)M0a') flag++;
if (ver =='15.2(4)M1') flag++;
if (ver =='15.2(4)M10') flag++;
if (ver =='15.2(4)M2') flag++;
if (ver =='15.2(4)M3') flag++;
if (ver =='15.2(4)M4') flag++;
if (ver =='15.2(4)M5') flag++;
if (ver =='15.2(4)M6') flag++;
if (ver =='15.2(4)M7') flag++;
if (ver =='15.2(4)M8') flag++;
if (ver =='15.2(4)M9') flag++;
if (ver =='15.2(1)S') flag++;
if (ver =='15.2(1)S1') flag++;
if (ver =='15.2(1)S2') flag++;
if (ver =='15.2(1s)S1') flag++;
if (ver =='15.2(2)S') flag++;
if (ver =='15.2(2)S0a') flag++;
if (ver =='15.2(2)S0b') flag++;
if (ver =='15.2(2)S0c') flag++;
if (ver =='15.2(2)S0d') flag++;
if (ver =='15.2(2)S1') flag++;
if (ver =='15.2(2)S2') flag++;
if (ver =='15.2(3)S') flag++;
if (ver =='15.2(4)S') flag++;
if (ver =='15.2(4)S1') flag++;
if (ver =='15.2(4)S2') flag++;
if (ver =='15.2(4)S3') flag++;
if (ver =='15.2(4)S4') flag++;
if (ver =='15.2(4)S5') flag++;
if (ver =='15.2(4)S6') flag++;
if (ver =='15.2(1)SB') flag++;
if (ver =='15.2(1)SB1') flag++;
if (ver =='15.2(2)SNG') flag++;
if (ver =='15.2(1)T') flag++;
if (ver =='15.2(1)T1') flag++;
if (ver =='15.2(1)T2') flag++;
if (ver =='15.2(1)T3') flag++;
if (ver =='15.2(1)T4') flag++;
if (ver =='15.2(2)T') flag++;
if (ver =='15.2(2)T1') flag++;
if (ver =='15.2(2)T2') flag++;
if (ver =='15.2(2)T3') flag++;
if (ver =='15.2(2)T4') flag++;
if (ver =='15.2(3)T') flag++;
if (ver =='15.2(3)T1') flag++;
if (ver =='15.2(3)T2') flag++;
if (ver =='15.2(3)T3') flag++;
if (ver =='15.2(3)T4') flag++;
if (ver =='15.2(3)XA') flag++;

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ("webvpn" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug IDs     : CSCtr86328' +
      '\n  Installed release : ' + ver +
      '\n';
    security_note(port:0, extra:report + cisco_caveat(override));
  }
  else security_note(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
