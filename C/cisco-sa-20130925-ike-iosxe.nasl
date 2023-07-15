#TRUSTED 47fb8c7e4cb0b126821f3e0e367e40eac647906bb88688d7136ddaf7215db88e7257bfdad0d39309fe00b3bf19ecb216ef2282290f5a0c1387ebc28531bc5872ac0fdde8ed4dfba8a5e78400937b0bad624cb95a046256bed860efd2c63e3c4c3fdd285e946a817376d5606ad7ec2d998aae2b600e42013088739faa7c09937bda228caab3a76d9693189684dfc39c3896fb8bb1f6269c486fb93d16c8d1486068518a75a78c94b53e6abe34cadf9ffa5291b0aaed1a702f42eafc2016802eba3bebbce72e0897c93b59bdc72c406707a5373972d68728509eaa83001f6346c1933390d7951bf25df01b8159df3be6622b356f789e9df75f60a4f6253ea06d798f0bf8beaa9844992d13da0f0565e015b5996013f58568c0d3ee1d023a2fe7bc0dcf309b38dc0452c24e20e6f9f553cd9c02cad68f2e609964fb3469414b06a22a36bef8f388be430910b474b2058afe32ae71c08b9222da0d456c5510440bdd89428683bfe12511bf52715abcaf8df9999f88dffb1385d6567acfe20f3dd898f1b1e6f9a24f473d146f7b30f1cdd48b83f5f8612d3dd55d9beb880074298a87fa0c21f2fb8987c2a41580dbbde358c4d293042c779651017432c338d0ce4bfbf355fc19ee873cbfb429241019d6282b6de0959521d4d6105322d9e7aac66b9547d1aea69421ce639e9b7019dd135278284e1849c699adc6f0083a93d7b849a3
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-ike.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70317);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-5473");
  script_bugtraq_id(62643);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx66011");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-ike");

  script_name(english:"Cisco IOS XE Software Internet Key Exchange Memory Leak Vulnerability (cisco-sa-20130925-ike)");
  script_summary(english:"Checks the IOS XE version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the Internet Key Exchange (IKE) protocol of Cisco
IOS XE Software could allow an unauthenticated, remote attacker to cause
a memory leak that could lead to a device reload.  The vulnerability is
due to incorrect handling of malformed IKE packets by the affected
software.  An attacker could exploit this vulnerability by sending
crafted IKE packets to a device configured with features that leverage
IKE version 1 (IKEv1).  Although IKEv1 is automatically enabled on a
Cisco IOS XE Software when IKEv1 or IKE version 2 (IKEv2) is configured,
the vulnerability can be triggered only by sending a malformed IKEv1
packet.  In specific conditions, normal IKEv1 packets can also cause an
affected release of Cisco IOS XE Software to leak memory.  Only IKEv1 is
affected by this vulnerability.  An exploit could cause Cisco IOS XE
Software not to release allocated memory, causing a memory leak.  A
sustained attack may result in a device reload.  Cisco has released free
software updates that address this vulnerability.  There are no
workarounds to mitigate this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfaf2180");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130925-ike."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
if ( version == '3.4.2S' ) flag++;
if ( version == '3.4.3S' ) flag++;
if ( version == '3.4.4S' ) flag++;
if ( version == '3.4.5S' ) flag++;
if ( version == '3.6S' ) flag++;
if ( version == '3.6.0S' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"crypto gdoi enable", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"crypto map", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"tunnel protection ipsec", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
