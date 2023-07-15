#TRUSTED 95d10d4ebc18108b0093049de956ccc3b7b1097d23e2a017f7802b119c659f055ef07586caa0acf4b08249192a3ddd2c54deb9ecb934af88b3e658f4218b9127573d93433f2ab58079fd01c8a5c2b9852fc1d43f75a05b9fbace8eb1dd70272ada30a9e9fa29b0b8171745c40269d652a42fc84f41de2ff9a418809b0ac02841e5873d6bc6142423e8d95ed731317742ca7b9fddb1dbdd6b7710746abf7a40c9dedfe2ffdd5d280d9cdce0fdb5b7e020d432384af8c9184dafc20c1192db232528ee6050089bf45104c479d044c5ccb8b030b9baa0a67686fa6bac70458fde6e140100b72301392dc0870087f38b343168f680944b36ff8944b8969a4b33ae3cd0997f902e27aa26013398cba6ec194d45fa3a2b5bfac11650d6e5d70eef955317a0271e83e02b4f023cb78001ec7eea6ec07aae1ff22c137ca42f6d88347a36c17c154818a18de2fa6146f8fcbe91056770e84e0b5b69ec502f779c1cb4cc253c96aabad3418d71771259b52afd3e0a01fc41a84a77169376297b2a2737adf445c8e99621c5244d561493f419b074fab63a758fe99a4755d6e328b4c3bd9bc4148c99e925a35a1336551815172d5ff151c2ec47eb1cea57b3c5092c465e1376533ef5d6c5e7925acd8a7e57ce72bf6947a4f2a42a9a14decb4927f76730abccaec0a65d40eb0a2d3642f2c0a64b66a12b2a4923efea46b1a8ff39dcbf111f90
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99665);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-6607");
  script_bugtraq_id(97933);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb40898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-asa-dns");

  script_name(english:"Cisco ASA Software DNS Response Message Handling DoS (cisco-sa-20170419-asa-dns)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a denial of service vulnerability in the DNS
code due to improper handling of crafted DNS response messages. An
unauthenticated, remote attacker can exploit this, via a specially
crafted DNS response, to cause the device to reload or corrupt the
local DNS cache information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-asa-dns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75ae1722");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb40898");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170419-asa-dns.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6607");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
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

if (
  model !~ '^1000V' && # 1000V
  model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower 9300 ASA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model != 'v' # ASAv
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

cbi = 'CSCvb40898';

if (version =~ "^[0-8]\.")
  fixed_ver = "9.1(7.12)";
else if (version =~ "^9\.0[^0-9]")
  fixed_ver = "9.1(7.12)";
else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.12)"))
  fixed_ver = "9.1(7.12)";
else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.18)"))
  fixed_ver = "9.2(4.18)";
else if (version =~ "^9\.3[^0-9]")
  fixed_ver = "9.4(3.12)";
else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(3.12)"))
  fixed_ver = "9.4(3.12)";
else if (version =~ "^9\.5[^0-9]" && check_asa_release(version:version, patched:"9.5(3.2)"))
  fixed_ver = "9.5(3.2)";
else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(2.2)"))
  fixed_ver = "9.6(2.2)";
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config dns server-group", "show running-config dns server-group");

  if (check_cisco_result(buf))
  {
    if (
      ("DNS server-group" >< buf) &&
      (preg(multiline:TRUE, pattern:"name-server [0-9\.]+", string:buf))
    ) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because a DNS server IP address is not configured under a DNS server group");
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    bug_id   : cbi,
    fix      : fixed_ver,
    cmds     : make_list("show running-config dns server-group")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
