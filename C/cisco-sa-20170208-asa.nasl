#TRUSTED 463f3ecd6f79675de8b73c89ac61c1bac3e4424b0356a777dc1353c3d1fd15c184fa7a36fd368b5eb61eb1d4d5114968987d68390245e440651309c3488df42c4b07d51e0f78bbdb1926e5a9d7fbd1502c80cc871ccb546cd0af11a257a46d67eb86c5aa082392ed4afc7042ea574562fcfd0623c9d38bc2cb3efeeddc866e551c6dfe112b55935ce5f0eee171d54e7c5e176f870bacfa60a512927e3ef2b10b1c4bd65debebcc3392ed74b86b1cd08bfbf47d83ef27abc15d5d885492f8f13027d3810aaf8940cba29817b738949b8b6104f58bdec6a458edb6e6b032beeba1aaeb8ca1c8c6dd0c82bc793eb94779d0655253693c819c7c4c54b5007ecaeb326bcdacee11c371ca8ad3bf91ead4f3a44ac188ce0538e6c4f3b8be2dbbf7acfa67c4c91331fd596ebd97937584b5cfeccc1a3ca48b79064f7fb0bdf760b42d570443abe63b60ee30a50c9a0d300f078d651cfc50534222bf5ff745b108ad17678541617469b62f8e743c519205ed35c83b78aa7b0ce38f6f874e73a91ef947a2651c02200f214307ba94d94458d7e3f9aab44622ad6b07609f239f828c86136ce4685f414297483e1800b2deca5b9ddd9aa1769bfc4102b3bb43ce1b09c96e485f5dd49375ca31bf77fb2b632506f0b7fafc48268058c427b477830fa920458c0680f5c8dfb9511c878536160c41f6c24d5b76183867790dc4d1a4e9cf7a9552
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97211);
  script_version("1.13");
  script_cvs_date("Date: 2020/01/16");

  script_cve_id("CVE-2017-3807");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc23838");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170208-asa");

  script_name(english:"Cisco ASA Clientless SSL VPN Functionality CIFS RCE (cisco-sa-20170208-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a heap overflow condition in the CIFS (Common
Internet Filesystem) code within the Clientless SSL VPN functionality
due to improper validation of user-supplied input. An authenticated,
remote attacker can exploit this, via a specially crafted URL, to
cause the device to reload or the execution of arbitrary code.

Note that only traffic directed to the affected system can be used to
exploit this issue, which affects systems configured in routed
firewall mode only and in single or multiple context mode. A valid TCP
connection is needed to perform the attack. Furthermore, the attacker
would need to have valid credentials to log in to the Clientless SSL
VPN portal. This vulnerability can be triggered by IPv4 or IPv6
traffic.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170208-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f26697b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc23838");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170208-asa.

Alternatively, as a workaround, it is possible to block an offending
URL using a webtype access list, which can be performed using the
following steps :

  1. Configure the webtype access list :

      access-list bugCSCvc23838 webtype deny url
      https://<asa_ip_address>/+webvpn+/CIFS_R/*
      access-list bugCSCvc23838 webtype permit url https://*
      access-list bugCSCvc23838 webtype permit url cifs://*

  2. Apply the access list in the group policy with the
     'filter value <webtype_acl_name>' command :

      group-policy Clientless attributes
       webvpn
        filter value bugCSCvc23838");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3807");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower ASA
  model !~ '^41[0-9][0-9]($|[^0-9])' && # Firepower ASA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model !~ '^(1000)?v$'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

cbi = 'CSCvc23838';

if (version =~ "^[0-8]\." || version =~ "9.0[^0-9]")
  fixed_ver = "9.1(7.13)";

else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.13)"))
  fixed_ver = "9.1(7.13)";

else if (version =~ "^9\.2[^0-9]")
  fixed_ver = "9.4(4)";

else if (version =~ "^9\.3[^0-9]")
  fixed_ver = "9.4(4)";

else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(4)"))
  fixed_ver = "9.4(4)";

else if (version =~ "^9\.5[^0-9]")
  fixed_ver = "9.6(2.10)";

else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(2.10)"))
  fixed_ver = "9.6(2.10)";

else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;
anyconnect = FALSE;

# Cisco ASA configured with a Cisco AnyConnect Essential license
# is not affected by this vulnerability.
# License info can be gathered with show-version (ssh_get_info.nasl) saves this
show_ver = get_kb_item('Host/Cisco/show_ver');
if (!isnull(show_ver))
{
  if (preg(multiline:TRUE, pattern:"AnyConnect Essentials/s+:\s*Enabled", string:show_ver))
    anyconnect = TRUE;
}

if (anyconnect)
  audit(AUDIT_HOST_NOT, "affected because this Cisco ASA device has been configured with a Cisco AnyConnect Essential license.");

if (get_kb_item("Host/local_checks_enabled"))
{
  # Check that webvpn is enabled on at least one interface
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config webvpn", "show running-config webvpn");

  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:".*enable outside", string:buf))
    {
      # Check that the ssl-clientless option is configured
      buf2 = cisco_command_kb_item("Host/Cisco/Config/show running-config group-policy | include vpn-tunnel-protocol", "show running-config group-policy | include vpn-tunnel-protocol");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline:TRUE, pattern:"vpn-tunnel-protocol.*ssl-clientless", string:buf2))
          flag = TRUE;
      }
    }
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the Clientless SSL VPN portal is not enabled");
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : cbi,
    fix      : fixed_ver,
    cmds     : make_list("show running-config webvpn", "show running-config group-policy | include vpn-tunnel-protocol")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

