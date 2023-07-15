#TRUSTED 301dfd42bd9ded9b6a3ad7c325e63fef1227722dce80f63a7f68c42da17804146bdae37c16f9face29da53235ed7d6dfb8ec6983d0836efa5b1c0e9d5be7781677a7eabc0677d83f95e1185b5873dfdb22c5a0abffd5ca3ddc37b5d0977e0306f74cbb86cdb39fdb008e4799b9e89f7d96ec0b25bda497ccf441de9e917de88cd6abc25216058d6814211f6d6f31ded69ec1e65ffb3a041c486574117aacae711f25ab28b4bfc07162dea7e5d3ee184316e862ac4f1f0b4dfc1011546302815b0826da422583bae99fc6f7dc7e1b892c0bb0481b41e15beba462c0e27ce283e41746d2351971e373003c355f209019bec24152cf2172c5189e1b58b6ce1107b33b5a182da1efcb1337085d75f9b297d1576004e60f44ed3520038da826478a613ad5a89d108c0bf01902e81f9f6f5ac4eff3a516c60c9beb552f6bea6045efa96c0256e9f57df51459c2b23abe042d66aecb0e7e83d4d79fa7e968bd2f21ec482bb180724d54b1730a09c1f2cad2e23d15245a97c9eefecf10dd4c36b7403aa718d2fdd9bda387fdff7a20ded22a8c54d1a726945af6de691dca478e8657ba27f692ecfeffa7d874cd05e52ba164841fbbadd57c764d325773337a87d8af6305fd9fba60276da0c7752d6cd683ee3daac85dabd110d1324d7bfa75c6b67f735b734a2a697171aaa18e17c7785fbbe367e5d76055bdeef0bb9ab5671f6cc8961d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73341);
  script_version("1.18");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id("CVE-2014-2108");
  script_bugtraq_id(66471);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui88426");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-ikev2");

  script_name(english:"Cisco IOS Software Internet Key Exchange Version 2 (IKEv2) Denial of Service (cisco-sa-20140326-ikev2)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability in the Internet Key Exchange Version 2 (IKEv2) module.
An unauthenticated, remote attacker could potentially exploit this
issue by sending a malformed IKEv2 packet resulting in a denial of
service.

Note that this issue only affects hosts when Internet Security
Association and Key Management Protocol (ISAKMP) is enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec115086");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33346");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-ikev2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}


include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
report = "";
cbi = "CSCui88426";
fixed_ver = "";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# 15.0ED
if (ver == '15.0(2)ED' || ver == '15.0(2)ED1')
         fixed_ver = '15.2(1)E2';
# 15.0EH
else if (ver == '15.0(2)EH')
         fixed_ver = '15.2(1)E2';
# 15.0EJ
else if (ver == '15.0(2)EJ')
         fixed_ver = '15.0(2)EJ1';
# 15.0EX
else if (ver == '15.0(2)EX' || ver == '15.0(2)EX1' || ver == '15.0(2)EX3' || ver == '15.0(2)EX4')
         fixed_ver = 'Refer to the vendor for a fix.';
# 15.0EY
else if (ver == '15.0(2)EY' || ver == '15.0(2)EY1' || ver == '15.0(2)EY3')
         fixed_ver = '15.2(1)E2';
# 15.0EZ
else if (ver == '15.0(2)EZ')
         fixed_ver = '15.0(2)SE6';
# 15.0SE
else if (ver == '15.0(2)SE' || ver == '15.0(2)SE1' || ver == '15.0(2)SE2' || ver == '15.0(2)SE3' || ver == '15.0(2)SE4' || ver == '15.0(2)SE5')
         fixed_ver = '15.0(2)SE6';
# 15.1GC
else if (ver == '15.1(2)GC' || ver == '15.1(2)GC1' || ver == '15.1(2)GC2' || ver == '15.1(4)GC' || ver == '15.1(4)GC1' || ver == '15.1(4)GC2')
         fixed_ver = '15.2(4)GC1';
# 15.1M
else if (ver == '15.1(4)M' || ver == '15.1(4)M0a' || ver == '15.1(4)M0b' || ver == '15.1(4)M1' || ver == '15.1(4)M2' || ver == '15.1(4)M3' || ver == '15.1(4)M3a' || ver == '15.1(4)M4' || ver == '15.1(4)M5' || ver == '15.1(4)M6' || ver == '15.1(4)M7')
         fixed_ver = '15.1(4)M8';
# 15.1MR
else if (ver == '15.1(1)MR' || ver == '15.1(1)MR1' || ver == '15.1(1)MR2' || ver == '15.1(1)MR3' || ver == '15.1(1)MR4' || ver == '15.1(1)MR5' || ver == '15.1(1)MR6' || ver == '15.1(3)MR')
         fixed_ver = 'Refer to the vendor for a fix.';
# 15.1MRA
else if (ver == '15.1(3)MRA' || ver == '15.1(3)MRA1' || ver == '15.1(3)MRA2')
         fixed_ver = '15.1(3)MRA3';
# 15.1S
else if (ver == '15.1(1)S' || ver == '15.1(1)S1' || ver == '15.1(1)S2' || ver == '15.1(2)S' || ver == '15.1(2)S1' || ver == '15.1(2)S2' || ver == '15.1(3)S' || ver == '15.1(3)S0a' || ver == '15.1(3)S1' || ver == '15.1(3)S2' || ver == '15.1(3)S3' || ver == '15.1(3)S4' || ver == '15.1(3)S5' || ver == '15.1(3)S5a' || ver == '15.1(3)S6')
         fixed_ver = '15.2(2)S0a or 15.2(4)S5';
# 15.1SG
else if (ver == '15.1(1)SG' || ver == '15.1(1)SG1' || ver == '15.1(1)SG2' || ver == '15.1(2)SG' || ver == '15.1(2)SG1' || ver == '15.1(2)SG2' || ver == '15.1(2)SG3')
         fixed_ver = '15.1(2)SG4';
# 15.1SNG
else if (ver == '15.1(2)SNG')
         fixed_ver = 'Refer to the vendor for a fix.';
# 15.1SNH
else if (ver == '15.1(2)SNH' || ver == '15.1(2)SNH1')
         fixed_ver = 'Refer to the vendor for a fix.';
# 15.1SNI
else if (ver == '15.1(2)SNI' || ver == '15.1(2)SNI1')
         fixed_ver = 'Refer to the vendor for a fix.';
# 15.1SY
else if (ver == '15.1(1)SY' || ver == '15.1(1)SY1' || ver == '15.1(1)SY2' || ver == '15.1(2)SY' || ver == '15.1(2)SY1')
         fixed_ver = '15.1(1)SY3 or 15.1(2)SY2';
# 15.1T
else if (ver == '15.1(1)T' || ver == '15.1(1)T1' || ver == '15.1(1)T2' || ver == '15.1(1)T3' || ver == '15.1(1)T4' || ver == '15.1(1)T5' || ver == '15.1(2)T' || ver == '15.1(2)T0a' || ver == '15.1(2)T1' || ver == '15.1(2)T2' || ver == '15.1(2)T2a' || ver == '15.1(2)T3' || ver == '15.1(2)T4' || ver == '15.1(2)T5' || ver == '15.1(3)T' || ver == '15.1(3)T1' || ver == '15.1(3)T2' || ver == '15.1(3)T3' || ver == '15.1(3)T4')
         fixed_ver = '15.1(4)M8';
# 15.1XB - no fix specified
else if (ver == '15.1(1)XB1' || ver == '15.1(1)XB2' || ver == '15.1(1)XB3' || ver == '15.1(4)XB4' || ver == '15.1(4)XB5' || ver == '15.1(4)XB5a' || ver == '15.1(4)XB6' || ver == '15.1(4)XB7' || ver == '15.1(4)XB8' || ver == '15.1(4)XB8a')
       fixed_ver = 'Refer to the vendor for a fix.';
# 15.2E
else if (ver == '15.2(1)E' || ver == '15.2(1)E1')
        fixed_ver = '15.2(1)E2';
# 15.2EY
else if (ver == '15.2(1)EY')
        fixed_ver = '15.2(1)E2';
# 15.2GC
else if (ver == '15.2(1)GC' || ver == '15.2(1)GC1' || ver == '15.2(1)GC2' || ver == '15.2(2)GC' || ver == '15.2(3)GC' || ver == '15.2(3)GC1' || ver == '15.2(4)GC')
        fixed_ver = '15.2(4)GC1';
# 15.2GCA - no fix specified
else if (ver == '15.2(3)GCA' || ver == '15.2(3)GCA1')
        fixed_ver = 'Refer to the vendor for a fix.';
# 15.2M
else if (ver == '15.2(4)M' || ver == '15.2(4)M1' || ver == '15.2(4)M2' || ver == '15.2(4)M3' || ver == '15.2(4)M4' || ver == '15.2(4)M5')
        fixed_ver = '15.2(4)M6';
# 15.2S
else if (ver == '15.2(1)S' || ver == '15.2(1)S1' || ver == '15.2(1)S2' || ver == '15.2(2)S' || ver == '15.2(2)S1' || ver == '15.2(2)S2' || ver == '15.2(4)S' || ver == '15.2(4)S1' || ver == '15.2(4)S2' || ver == '15.2(4)S3' || ver == '15.2(4)S3a' || ver == '15.2(4)S4' || ver == '15.2(4)S4a')
        fixed_ver = '15.2(2)S0a or 15.2(4)S5';
# 15.2SNG
else if (ver == '15.2(2)SNG')
        fixed_ver = 'Refer to the vendor for a fix.';
# 15.2SNH
else if (ver == '15.2(2)SNH' || ver == '15.2(2)SNH1')
        fixed_ver = 'Refer to the vendor for a fix.';
# 15.2SNI
else if (ver == '15.2(2)SNI')
        fixed_ver = 'Refer to the vendor for a fix.';
# 15.2T
else if (ver == '15.2(1)T' || ver == '15.2(1)T1' || ver == '15.2(1)T2' || ver == '15.2(1)T3' || ver == '15.2(1)T3a' || ver == '15.2(1)T4' || ver == '15.2(2)T' || ver == '15.2(2)T1' || ver == '15.2(2)T2' || ver == '15.2(2)T3' || ver == '15.2(2)T4' || ver == '15.2(3)T' || ver == '15.2(3)T1' ||   ver == '15.2(3)T2' || ver == '15.2(3)T3' || ver == '15.2(3)T4')
        fixed_ver = '15.2(4)M6';
# 15.2XA - no fix specified
else if (ver == '15.2(3)XA')
        fixed_ver = 'Refer to the vendor for a fix.';
# 15.2XB - no fix specified
else if (ver == '15.2(4)XB10')
        fixed_ver = 'Refer to the vendor for a fix.';
# 15.3M
else if (ver == '15.3(3)M')
        fixed_ver = '15.3(3)M1';
# 15.3S
else if (ver == '15.3(1)S' || ver == '15.3(1)S1' || ver == '15.3(1)S2' || ver == '15.3(2)S' || ver == '15.3(2)S0a' || ver == '15.3(2)S0xa' || ver == '15.3(2)S1' || ver == '15.3(2)S2' || ver == '15.3(3)S')
        fixed_ver = '15.3(3)S1';

if (fixed_ver) flag++;

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^crypto map", string:buf)) { flag = 1; }
    if (preg(multiline:TRUE, pattern:"^tunnel protection ipsec", string:buf)) { flag = 1; }
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
