#TRUSTED 2b1228c237110ac00eb377a41bbfc621080ff7fe1e46988c83bf0cd37c6a007bd6e02e7486567e299f467960bbdb133857148438fdcd7dc1f3eac3eaec129f6a1716bffed033489ab190de2f524fdea3f288f74d8636fc72548e07d9d85dc3ff3f828cd3008d0ad55984dea1130ba1e0da6e17be436f3d3caf85444653fb597b6a37940e062eab765ab5a5dd695d0f3d47828f1b2b3126d2bd5d5dccb2a02c7fc69f03367dc37f7f935f00e62f05dbad79672d58bda6e3002b2263c312b2473a793daf8895d6028c1cfe9ed7e5a96533fa2cf0a861f05f35008d98aad101a64e38cef512eb650b19444d4daff71be3d75f870958227fb9dbb2096ce2ca8465052ce749873cab8dddf1e3d418e22f9d05622bb84d5ef2ea9c1fd668e09f71f2d3938a04b2a0a8f59840ceab9702e95d45815bf81f9a4ddf9828d8895c3bad7a6d7634e83a9369c263109191850ce143a4078444d73e948639e22ae52567325d0ec410507ffb8d7ea1a59410b04c2d0d0855506dcf3d620dd53cbf831e283a8bf42467d33c5a1d197f53ca0b8d9bf210b46100259ff6df915980b3749825dd71b8b6693c5323129a31f6272c1983757dec5f910b20ecce71236924fe9fae7dc2437de0656a6647b60602c20950eb1f1164cf1b769cc77f5ed0f7bfcaf695a5e2ac6ba74fbbcfbf23f6f113ac3aac631fe8f7ad3914921d4b8375774215a30d50a4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92630);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-1445");
  script_bugtraq_id(91693);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy25163");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160711-asa");

  script_name(english:"Cisco Adaptive Security Appliance ICMP Echo Request ACL Bypass (cisco-sa-20160711-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Adaptive
Security Appliance (ASA) software running on the remote device is
version 8.2.x or 9.4.x prior to 9.4(3.3), 9.5.x prior to 9.5(2.10),
or 9.6.x prior to 9.6(1.5). It is, therefore, affected by an ACL
bypass vulnerability due to a flaw in the implementation of ACL-based
filters for ICMP echo requests and the range of ICMP echo request
subtypes. An unauthenticated, remote attacker can exploit this, by
sending ICMP echo request traffic, to bypass ACL configurations on the
affected device, allowing ICMP traffic to pass through that otherwise
would be denied.

Note that ICMP must be enabled for the device to be affected by this
vulnerability.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160711-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4fa89b9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy25163.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');
fixed_ver = NULL;

if (ver =~ "^8\.2[^0-9]")
  fixed_ver = "Refer to vendor.";

else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(3.3)"))
  fixed_ver = "9.4(3.3)";

else if (ver =~ "^9\.5[^0-9]" && check_asa_release(version:ver, patched:"9.5(2.10)"))
  fixed_ver = "9.5(2.10)";

else if (ver =~ "^9\.6[^0-9]" && check_asa_release(version:ver, patched:"9.6(1.5)"))
  fixed_ver = "9.6(1.5)";
if (isnull(fixed_ver))
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

flag     = FALSE;
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_accesslist", "show running-config | include access-list");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"permit icmp", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

security_report_cisco(
  port     : 0,
  severity : SECURITY_WARNING,
  override : override,
  version  : ver,
  fix      : fixed_ver,
  bug_id   : "CSCuy25163",
  cmds     : make_list("show running-config | include access-list")
);
