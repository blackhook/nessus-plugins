#TRUSTED 2b1bf7f47c8568a37b243a6a867437c51253e5d545fe3f6d2380962a5890cb00b171888ca98d4f77fd8e302ac282bd8eee1ebf8f19e25704e246cdfd3f194fac079df8abcb6e4acfacdb563f9af2661d4ff0945b869cd07d9220356d2f4c34e04f5f51a6f0ba23c2edab1dec72fc9d02422b62387bd0dd2636f4a85c5db63a3c736f4be24a5b224db195dee1cd997a5802d35d7469a5e0fdaf1c8a09b6e03de36543ca7387e2183c444c5a1003d436a3557e17f6f6cab83dc4d2c89611cdd11bec0eb0559e09a6d2c5b1d2dedf2a94442723fb52a1cfd680a00824c2759986c59e27220612db1db84c91226ce978f250dd32c3a05fc36ad7137f892d3d6e7acd7f77c4da2733db65cfeb996b658e53c198cd5cd28a4f0957de0e75c813b4c16cea982a55c02952c4f9df4dc326082d2025f2676bf60b64c8235505e19e4f9322c36062f27ce6b93160dfa349b9b0693fd590116caf60f5233cfc9ac6bf77dba0f3a2d129b0afe513fe0c80deebb341b17dc694e711627bd40cd6bba511d32ebce24fe92c17b7b9917071a8e364502d071640d797041eb03243ec8c81273c7acb20ed7997576a689edcf77a1cb3b53230e5c2a3f3208c8fadb1beb53dacd1d2da2dc38e382bc19ae0d9c4d46ed3d053f024e866298eaa9c519e8da038e7dd60dde1b8ce0b62085f36b486543893f109d607cd3889b7bb30b202ad9558737522c0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90307);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2016-1351");
  script_bugtraq_id(85309);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu64279");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-lisp");

  script_name(english:"Cisco IOS Malformed LISP Packet DoS (CSCuu64279)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS software running on the remote device is
affected by a denial of service vulnerability in the implementation of
the Locator/ID Separation Protocol (LISP) due to improper input
validation when a malformed LISP packet is received. An
unauthenticated, remote attacker can exploit this, via a crafted
packet, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-lisp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3df085d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuu64279.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1351");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

model   = get_kb_item_or_exit("Host/Cisco/IOS/Model");
if (model !~ '6[58]{1}[0-9][0-9]([^0-9]|$)')
  audit(AUDIT_HOST_NOT, "Catalyst model 6500 / 6800");

flag     = 0;
override = 0;

if (version == "15.1(1)SY1") flag = 1;
else if (version == "15.1(1)SY2") flag = 1;
else if (version == "15.1(1)SY3") flag = 1;
else if (version == "15.1(1)SY4") flag = 1;
else if (version == "15.1(1)SY5") flag = 1;
else if (version == "15.1(1)SY6") flag = 1;
else if (version == "15.1(2)SY") flag = 1;
else if (version == "15.1(2)SY1") flag = 1;
else if (version == "15.1(2)SY2") flag = 1;
else if (version == "15.1(2)SY3") flag = 1;
else if (version == "15.1(2)SY4") flag = 1;
else if (version == "15.1(2)SY4a") flag = 1;
else if (version == "15.1(2)SY5") flag = 1;
else if (version == "15.1(2)SY6") flag = 1;
else if (version == "15.2(1)SY") flag = 1;
else if (version == "15.2(1)SY0a") flag = 1;
else if (version == "15.2(1)SY1")  flag = 1;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_lisp", "show running-config | include lisp");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^router lisp(\s|$)", string:buf))
        flag = 1;
    }
    else if (cisco_needs_enable(buf))
    {
      override = 1;
      flag = 1;
    }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : "CSCuu64279",
    cmds     : make_list("show running-config | include lisp")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS software", version);
