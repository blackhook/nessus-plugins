#TRUSTED 39d780f1da0fad071722b2f17aaedb8fdb07675966f6399c897a728bb9307c4c0b39f6416568c4d5259014a7581aa1cf688d81b9c1014c25e9dc90b2f19b6162be38960959e01af948108d30ada4b575eae6fb5eb0ceaf98e01205e4ebbf06c99636727988baab2bef6de2293db3b9c0812a81d85971b55b51d73194e431f9c752bbe29cda607d8594132ac5d58a4ca989a048181c4266e4f1224dd5172e0e3739ee59743a26d87f5744e7ef14a4b9db8e52eaef8d1f98fdfe62b9027c6807a9fb5a774c1dbc667c94a87491e90942e984d7a98f92626a623255fee4dd7b896be1b37fc1dc94f0a0661cba144001a041fdea54ed282493ed1fb07cd046f49fb312a8c8f3eb9db48c8088df1ff1d0c71b845eecc50a957b805333b99fa11d9dab7e22299a318d1241e2c09c023be1503d7a3d2ddb07c1dad0b0dab08e79d0d50609adc4a0da797d6ad03ad7f565fbdcf13309198028a8bc219efc9cc516f9cecfbfe6bc828a095056768597c9ce61ffd6cad1b3310b5b6821df7aef94760bff848347d68a312a08947fd886847c6ebd0954bfadab4c6236e4c1b125f690ff6c3cf15cc264cae52dddf1b6c59754d0ed4b44c644e7bed25f14f9706d96ec10bf2fa1e42685afebc1949105a491ba56d2580d5a4e3893fe02d6888d8dc365fddfb8f0d67bf810996dbf5ec673617857ce8834ef51720d9522ef1b2d9f1f931c2fd5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99233);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_name(english:"Cisco IOS Smart Install Protocol Misuse (cisco-sr-20170214-smi)");
  script_summary(english:"Checks the IOS configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The Smart Install feature is enabled on the remote Cisco IOS device.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS device has the Smart Install feature enabled. The
Smart Install (SMI) protocol does not require authentication by
design. The absence of an authorization or authentication mechanism in
the SMI protocol between the integrated branch clients (IBC) and the
director can allow a client to process crafted SMI protocol messages
as if these messages were from the Smart Install director. An
unauthenticated, remote attacker can exploit this to perform the
following actions :

  - Change the TFTP server address on the IBC.

  - Copy arbitrary files from the IBC to an
    attacker-controlled TFTP server.

  - Substitute the client's startup-config file with a file
    that the attacker prepared and force a reload of the IBC
    after a defined time interval.

  - Load an attacker-supplied IOS image onto the IBC.
  
  - Execute high-privilege configuration mode CLI commands
    on an IBC, including do-exec CLI commands.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170214-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc0b0179");
  script_set_attribute(attribute:"solution", value:
"Disable the Smart Install feature.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2020 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;
override = 0;

cmds = make_list();

buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
if (check_cisco_result(buf))
{
  if ( (preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient", string:buf)) &&
       (!preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient\s+\(SmartInstall disabled\)", string:buf)) )
  {
    cmds = make_list(cmds, "show vstack config");
    flag = 1;
  }
}
else if (cisco_needs_enable(buf))
{
  flag = 1;
  override = 1;
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_NOTE,
    override : override,
    version  : ver,
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS", ver);
