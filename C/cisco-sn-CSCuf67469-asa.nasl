#TRUSTED 640787f5ead9c950d083ef8c1583f1cffc46a18e843d2ec06f0094e199e352609e9cb78506755e06e2b9a3ea9573c383d84b495424718ce4b57e78a6ded38895071a9a972afa05c178290dc9675fcf299e5630bc05d23b5d9529f1a317ed1acb6dfb8e7742616345346e352d75c653c130a8d89863494f7264ea29e85409a89666299b5767b0f03c8e5ec057cbee6a0afb74d45c2c181395579738f0395a707a525ebd6d544450d0a448a0a9d07ded398b761b932eff29d4c9cc98fd436851fd892e9f00d4a9d1921e4df7b521b11a3ca22eb58654c02c628e19d22a99ebc0467217588ed6c701223db1cfb128165a2e2e44eac4522810c9786d29da81e9b523d74424a029362d381f11fa62f2253c641f36119a174e753d0fd0aa88b45f772ff8b83d0a26c554732c6509576fc3208c1de6a4b71e21658d6d47229dd578ef3f4efee4b20ffa878f024b8634bd11ddd3c2298b3d2c5fbc185e9177d857e9a105aadaf092a26021b8ded4fcc3d7c221243bd62fa7ad3f2d965076b6f3b5c03e5e74c1962cdd1160943af20cc747c215fb7581fd68601243b40d97bbc794fbc49253b8f67e2435507cdc3cba8c43c584015f3255498fa2ac5c01be3d76bdb528af34293e4881188274ee9f5cf99aa42ba48a2926103a4ab52ba9e61b9ed371c4687e467060cc2acfc6e5b4fff444319788a40ed48e0281f51d3eb21acbb5b300f0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73827);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-2154");
  script_bugtraq_id(67036);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf67469");

  script_name(english:"Cisco ASA SIP Inspection DoS (CSCuf67469)");
  script_summary(english:"Checks ASA version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) Software contains a
vulnerability that could allow an unauthenticated, remote attacker to
cause a memory leak which can be exploited to create a denial of
service condition.

The vulnerability is due to improper handling of Session Initiation
Protocol (SIP) packets. An attacker could exploit this vulnerability
via specially crafted SIP packets.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=33904
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f31a15d");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Bug Id CSCuf67469.

Alternatively, the vendor has provided a workaround that involves
disabling SIP inspection on the affected device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

# Cisco ASA 5500-X Next Generation Firewall
if (model !~ '^55[0-9][0-9]-?X') audit(AUDIT_HOST_NOT, 'ASA 5500-X');

temp_flag = 0;
if (get_kb_item("Host/local_checks_enabled")) local_check = 1;

if (
  cisco_gen_ver_compare(a:version, b:"8.4(5)") == 0 ||
  cisco_gen_ver_compare(a:version, b:"8.4(5.6)") == 0
)
  temp_flag++;

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_service-policy-include-sip",
      "show service-policy | include sip"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, icase:TRUE, pattern:"Inspect: sip", string:buf))
        temp_flag = 1;
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.4(6.1) / 8.4(6.99) / 8.4(7)' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
}
else audit(AUDIT_HOST_NOT, "affected");
