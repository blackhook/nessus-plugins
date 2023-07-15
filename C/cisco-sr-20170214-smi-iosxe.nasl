#TRUSTED 30ed5bda9f38bcab817a6c71fe036ac0e0c1f1fa1c96dc3a0dfa55402c39f5b52c56947486690ba72e2df9efdf83c9664332ab21ec95217212c39ffdd97be422d01b1cd46be89bc03149bcfe57b02f4ae90b54915980d4fae2abb99644360073ffc4d69506d9930b5d8fa5c3187c1b0ef10925e430005d3d582d874f5dc464f31eac0fa35f7bf3b7c2db5e9f2f001ef894b78405519fba5ebf0abe1ca923f91e893438ff0b75e636b95a90286d0fa45ccb54a6600674b568088f890b67cdf80748102b44ea05c3b8f2f8d0ee8d4d20640235c8bc729624ca28500f2c9370eeefec98849704ef8540f646f98379a1b223bd1f78d56e405cdcc50064e7a7e403b9bf5f873c1681d7641605d50ebc22e5ca39179c208cb1782a2474de4b1732cd4b22f77cf15628d9a61828f0609d9a3427965d23222bc21ad27026970906b9ffd06551dd4338d6dc9aafd6d8676312f89dc9632901b94b80429ef84ce962c1d273ab024dc568e714dabc5c9e22de6801bdd7a2f86b98606d4423e365a3ea4da41dc13a1e21518bbd12c17b00305f91d94b1261e4151ff345c7c64618a56fc08b9789c5a313cef571b4bb107701a6783ae41e72164fe39e06309028ac6c968c360bfbefbeb886515927d1d1aa3d611b8764acc9daafb79dcc3233bee70814b488693eacad0d6d113f105e8d110fc35b319723f6f357c754c5590f96f797110985eb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99234);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_name(english:"Cisco IOS XE Smart Install Protocol Misuse (cisco-sr-20170214-smi)");
  script_summary(english:"Checks the IOS XE configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The Smart Install feature is enabled on the remote Cisco IOS XE
device.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device has the Smart Install Feature enabled.
The Smart Install (SMI) protocol does not require authentication by
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

  - Load an attacker-supplied IOS XE image onto the IBC.
  
  - Execute high-privilege configuration mode CLI commands
    on an IBC, including do-exec CLI commands.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170214-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc0b0179");
  script_set_attribute(attribute:"solution", value:
"Disable the Smart Install feature.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

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
else audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
