#TRUSTED 04df52dff6cc2e7fc37b5d95a45b130ecc2afcf7fa244403434dcfd885be6cd4ceb9bd21d6f5a859b840909f543cd4fca9114ab95bb87ba7dd49a2b4398b1515a9f7ab906d32883ca99b6d0c5171000610986940601b774f48106ab6173b821c5cd8c0c3acc5da8b3bfc83684765905fa00fe088f24e35814c62c057b56fa8347a8b0f1d4830815d0d2d7a469da9caa3cf225640734348f0e7ec8575d16444bb32c2fb0df7051349af6f3d07d92f1d92cd87b43d855681571d51cfc5aa9cdbc3206f28ceef7dccba01fe456d2cbed43ff78556bb84e0c86f981f1f2cd57bcd57c394712e20d01d7d0abf689b58432fe4249ee7d44fd2cdab67f2909a4ca9250437179642257602414d751140cbba5a9a47aa9b4fa99347ccca5469e9be1912e123f90df20a9872a5436b30c59e30988086a1f2f3590a579848b39dbadc7765ad90dadd3eb1df9d1203f87730d257fc460a30bf9b9c67694a3f7b0a825a5480f68e3d01873653fd8c72f4eb8795d5ed11ac1b140a12aad084acb75687841780d495a67ccff0d4d20191330ebdc9d788c67bb56b109064e7e94a8b87737e939b80b083241bb4076640a6c826a63354fbfecb939e9ecc2440b6997296b9da20dfcc25a32ac810d87ced90e47c0e0ab4acb8d2dc1ab90403538b1c8923b9cd1f7f16c12b1d1bbc73a0e1b6260246e6e3d9f3279607d57a507a06a53f1fb605006679
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130327-ike.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(65886);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-1144");
  script_bugtraq_id(58742);
  script_xref(name:"CISCO-BUG-ID", value:"CSCth81055");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130327-ike");

  script_name(english:"Cisco IOS Software Internet Key Exchange Vulnerability (cisco-sa-20130327-ike)");
  script_summary(english:"Checks the IOS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS Software Internet Key Exchange (IKE) feature contains a
denial of service (DoS) vulnerability. Cisco has released free
software updates that address this vulnerability. Workarounds that
mitigate this vulnerability are not available."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130327-ike
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92e657e9"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130327-ike."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/11");
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
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)T4' ) flag++;
if ( version == '15.1(1)T5' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)GC2' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(2)T5' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"17\s[^\r\n]*\s(500|4500|848|4848)", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_subsys", "show subsys");
    if (check_cisco_result(buf))
    {
      if (!preg(pattern:"ikev2\s+Library", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
