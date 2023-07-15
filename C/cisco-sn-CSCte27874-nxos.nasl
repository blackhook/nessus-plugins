#TRUSTED 4e466fbd2a83dd439e512e69f109cb23b22428698c7b5503f86d24332d5576934c82504bdd4f94e2aa7f37a0e5a32e0b57b64672c4e939ec2859d053551ed6d6f3f0a2eb780d5ccb28b356b615eebde02e79ed12aee86bfb6c0f713d0159a4b924883c01bbf1845ce13e3ef3fd8bb56b990b53f722c8d94ff3353bf2a6e594b0bf5c4173557e18b8bf6234c1f381a2a47474d561122bbdb624d16817e648d21f8a0a9ab727fb38c13e86cbd66288a7a72ee9669c2eb96551e0bfc7696330874214044ff0bcbe92b4f3b5e4e4279891c14a566cdcea669437c082f0cf226209b29d9220b4a40cc0f597ac511d9be2e201d70d4f09af28329c9c5c0a4d8706d7d75bf17fda8648fcc68d24c887b35db53ae3f7bfcb4f720d5e0ac0f28880d870350aa5e43d4ffdae450e2fd13bde544cda494ef92d65c45d81c51e9a039325e5aef299dedf813d7510502c5e1b6b8ac1ab4a7621e6ee68687c10fc84b9c6ef85017f26e8beee7f17b3906bddbcf75700e9e774c1dd33b832f0664b12b371b4e38c415ffb73ed1dc0fbb6434d4e5ad6d623a0e7bab72385740ee9185b93a0936816e0d0a273b4af99e15547db81d92b9781fa025435b51da84002c8f62fb5349d0ffbd80a6940b5c8e919c5b4e117ef7748e0fa4b2d944854c184b9fd8a582cbe42b1f5244016127638faebccb8131f326cbe80a5f091a757ee2cd0ae25dc2fde34
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78557);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/10/29");

  script_cve_id("CVE-2013-5566");
  script_bugtraq_id(63564);
  script_xref(name:"CISCO-BUG-ID", value:"CSCte27874");

  script_name(english:"Cisco MDS 9000 VRRP DoS (CSCte27874)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is an MDS 9000 series router. It is, therefore,
vulnerable to a denial of service vulnerability. A flaw with Virtual
Router Redundancy Protocol (VRRP) frame handling allows a remote
attacker, using a specially crafted VRRP frame with an Authentication
Header (AH), to cause the device to have high CPU utilization and
force a restart of the device.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31663
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec5d4ba1");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31663");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in Cisco bug ID CSCte27874.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2019 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# only affects MDS 9000 series systems
if (device != 'MDS' || model !~ '^9[0-9][0-9][0-9]([^0-9]|$)') audit(AUDIT_HOST_NOT, "affected");

flag = 0;
override = 0;

if (version == "2.1") flag ++;
if (version == "3.0") flag ++;
if (version == "3.2") flag ++;
if (version == "4.1") flag ++;
if (version == "4.1(1b)") flag ++;
if (version == "4.1(1c)") flag ++;
if (version == "4.1(3a)") flag ++;
if (version == "4.2") flag ++;
if (version == "4.2(1a)") flag ++;
if (version == "4.2(1b)") flag ++;
if (version == "4.2(3)") flag ++;
if (version == "5.0") flag ++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_aclmgr",
                                "show running-config aclmgr");
    if (check_cisco_result(buf))
    {
      if (!preg(multiline:TRUE, pattern:"interface mgmt0", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCte27874' +
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra: cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
