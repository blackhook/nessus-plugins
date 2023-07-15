#TRUSTED 6355abb6bf5ba285194b8d0b4535aed2f6ca1c3880b823422b5de22aad999a45ee5a9007c2bbfee1111a4c933696c2311e1b4ba7329f48bb62a9b69c2f336dc8444fd68392f05b5a4bad255cc5a73e0cf514ba4bd5b17d4d0babf0ac89bcf47308408887c674fea1582d25ee089bbaa41c25ad2af20d2c12bf30f7e8d131c0eea6287f1faa818bd301b44afa21efa8c3f57562798d4a4e5570054b24e6767a3fbb076ea7fc25ff96af7bd1836b63c497cc8ca7318974ffc3229d22b7ce91ebf0e0d08c5348a7e21a3b5b8dafb1a4236b0144f4f7f52064553c1bba8177048c37e427b992aedc43310c9e634320e14d78af3bcd37793e0e37b57e1b6392c312fb3ddd41bdda2d11e451761bc7753df66157e26be511273d95b05ad925e067cdc3083ce155e51ab3687ff154701464365d2557283ea4b4459e1eaab1024cb70b42f622e3ac0c7666e284491690c771035a7852cbc9b4586281773ea9ebd50fb2f4bd03bf531aad665bcbced6e7be19e1b866b5b838c46c1b5c7bd2ff5d8f113dba26423088718193f417fcb3143a2d590acc5f56e38081e9ef4ffd11eefee12e15eada421454c35a8f1c2ff218c81b64ccb14cc197992d381ae05f8c1a0b88bbc59022e32987cfef505ff7384c20b31a8e3e900e55af1e124679c0617693b46585ff804b6baa54383af95e76346cfa5b09bf5c60c9c7742fb514eddb4860d6ac1b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73344);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-2113");
  script_bugtraq_id(66467);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui59540");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-ipv6");

  script_name(english:"Cisco IOS Software IPv6 Denial of Service (cisco-sa-20140326-ipv6");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability in the IPv6 protocol stack. This issue exists due to
improper handling of certain, unspecified types of IPv6 packets. An
unauthenticated, remote attacker could potentially exploit this issue
by sending a specially crafted IPv6 packet resulting in a denial of
service.

Note that this only affects hosts with IPv6 enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ffd6d00");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33351");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-ipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
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
report = "";
fixed_ver = "";
cbi = "CSCui59540";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

#15.2E
if (ver == "15.2(1)E" || ver == "15.2(1)E1")
  fixed_ver = "15.2(1)E2";
#15.2EY
else if (ver == "15.2(1)EY")
  fixed_ver = "15.2(1)E2";
#15.2GC
else if (ver == "15.2(4)GC")
  fixed_ver = "15.2(4)GC1";
#15.2JA
else if (ver == "15.2(4)JA" || ver == "15.2(4)JA1")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2JAY
else if (ver == "15.2(4)JAY")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2JB
else if (ver == "15.2(4)JB" || ver == "15.2(4)JB1" || ver == "15.2(4)JB2" || ver == "15.2(4)JB3" || ver == "15.2(4)JB3a")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2JN
else if (ver == "15.2(4)JN")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2M
else if (ver == "15.2(4)M" || ver == "15.2(4)M1" || ver == "15.2(4)M2" || ver == "15.2(4)M3" || ver == "15.2(4)M4" || ver == "15.2(4)M5")
  fixed_ver = "15.2(4)M6";
#15.2S
else if (ver == "15.2(4)S" || ver == "15.2(4)S0c" || ver == "15.2(4)S1" || ver == "15.2(4)S2" || ver == "15.2(4)S3" || ver == "15.2(4)S3a" || ver == "15.2(4)S4" || ver == "15.2(4)S4a")
  fixed_ver = "15.2(4)S5";
#15.2XB
else if (ver == "15.2(4)XB10")
  fixed_ver = "Refer to the vendor for a fix.";
#15.3M
else if (ver == "15.3(3)M" || ver == "15.3(3)M1")
  fixed_ver = "15.3(3)M2";
#15.3S
else if (ver == "15.3(1)S" || ver == "15.3(1)S1" || ver == "15.3(1)S1e" || ver == "15.3(1)S2" || ver == "15.3(2)S" || ver == "15.3(2)S0a" || ver == "15.3(2)S0xa" || ver == "15.3(2)S1" || ver == "15.3(2)S1b" || ver == "15.3(2)S1c" || ver == "15.3(2)S2" || ver == "15.3(3)S" || ver == "15.3(3)S0b" || ver == "15.3(3)S1" || ver == "15.3(3)S1a")
  fixed_ver = "15.3(3)S2";
#15.3T
else if (ver == "15.3(1)T" || ver == "15.3(1)T1" || ver == "15.3(1)T2" || ver == "15.3(1)T3" || ver == "15.3(2)T" || ver == "15.3(2)T1" || ver == "15.3(2)T2")
  fixed_ver = "15.3(2)T3 / 15.3(1)T4";



if (fixed_ver) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
    if (check_cisco_result(buf))
    {
      if (preg(multiline: TRUE, pattern:"IPv6\s+is\s+enabled", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
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
