#TRUSTED 78fe4bb6cb9c36287e94eed521496b4d18f55fdcdee5cc7c0dea2e210b3f9f63a509afa56f735862f16dad2a1907296527faa466c19ca59e2a468b47aee0843fe1e996b66b225bb0ad72b5d30a97e603da09b4c27715ba5973cfd27474ba941015eff8018973328f99f661e559f558c44deddcea9c2198d07a726580d238d769d96fbdc4a50ea11578699efe0f69b9462c6f0fba18009e8ff39cfb413e65c1824d17ac971b7dd332038682877f7a8ecd504dda86ad087c9c11357e6d3243646e8073457df9c82c2b13b4ee2c0323e77f44ae84e28db2bb4c02c4b0a5c2389bf08226e8529d3c3ba89dfd80671297a728cded167131b9e3888415654437224a65203896142fd0dc8e519f1217112bff8c3bdd30eb717c810e697135fa908b7da7f86f579bbe59649585c4ed8417865d26e79add6e45ed2bd5e82c6afbd5971e9c6fbed8a8294ecb6e7e8d4d25b9720ce303667701a71b572b80f2dd163d34b9bab3bd65eb083e1638287d9364d471f714df02b3a69b12d88c9ba6b6a4e5df6fceee2737ace41d5164ca33f4dff1ace1ba8236836eb68840a962c5ab68c4d64ce1798d392a9ca342105b61daa8216050cd0ec862b6bd4ed91aad1e16a98ba55f42ef13c21d62e04bf1dd11f1e75e6f23c777ea4d24256be0056aa94007e1b2c773ecbf53d9e20d220a0680c2f601fcb8dcde39ff878dd2e839f5340facbd09f311
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90714);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-1367");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160420-asa-dhcpv6");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus23248");

  script_name(english:"Cisco Adaptive Security Appliance Software DHCPv6 Packet Handling DoS (cisco-sa-20160420-asa-dhcpv6)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) device is affected
by a denial of service vulnerability in the DHCPv6 relay feature due
to improper validation of DHCPv6 packets. An unauthenticated, remote
attacker can exploit this, via specially crafted DHCPv6 packets, to
cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-asa-dhcpv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ac65dfd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus23248. Alternatively, disable the DHCPv6 relay feature.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1367");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/26");

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

# Affected :
#  Cisco ASA 5500-X Series Next-Generation Firewalls
#  Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers
#  Cisco Adaptive Security Virtual Appliance (ASAv)
if (
  model !~ '^55[0-9][0-9]-?X' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model != 'v'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500-X/6500/7600 or ASAv");

fixed_ver = NULL;

if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(1.1)"))
  fixed_ver = "9.4(1.1)";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if DHCP6 relay is in play
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-ipv6", "show running-config ipv6");
  if (check_cisco_result(buf))
  {
    if ("ipv6 dhcprelay enable outside" >< buf) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because DHCP6 relaying is not enabled");
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
