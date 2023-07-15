#TRUSTED 35f107ae37aa835692fb604141a55aa25d79f0e89354f64a68d2d45547166abaa8658def0bc90b94261218c4935519110db5f14123789dc51b6110d2ca2328a7d4687a4d23d364972bb79ef3007e18474ed3075db8f8952abef30954860dfe982ccccc0b0fc2afd41d7f4b36492fd874e1022089d4f2b0c0663adeea227f67e98a894b16048b1e919727efd4c713d32770435b2a71a7d3bec4336198b37b88ffad75d779f4f71bfc135b2bf2b31c9dd95b4196c0e865d567542e9030017d026a0be794990f650390d509ed922995154ce9846a1a829436949a2740ec62c142daba2152b240e2d18cc0c17546c732fa45b2df1489928ae2cdf1785e9e7d0fcf1466be78e9d4b32ac432beabbbba96fa1226eda7afe8487dbd9146afd8e1769e8b3b992e7c96e6799c378abef315e470f3b2e3f19bd2d7654ece26979e15a9f7b39e0c974178a2fecb4ec493fb42247ee70115ae7d2f88128176825aaf3c160f34542174738917b6d885d7237f38075b865965e2f4d85fb39695fb3f0a9c68661f39c672187068a71ea8b9a9f50069988b88d921e9668a6f3ec7bddc3e2b36f35980f24acc865ac4e4da7044a27c4ab44ac8f1de56ba64bd0a4636c4a956e746e8a41c0b198bcda394dc6a2a19657029d3b0b29d68af97905ad700bf6585548456a53afef44e65df78d5a07d82961cc398867db38bf600e66f608841acfb10d381
#TRUST-RSA-SHA256 7a41d83a7d5dbce0872d70c4d094f92087bfcf9d32286571cbbdb76a56144b6a683c573f87473a9a2643604e1fe055b7265f31cd3a894c5a1787e155602aa581b7596aef9a9e981b0223b2d255b4ddea36714477548cda00e42ab48d371c31574c8a8e9bce1b45f021e3f1111a1c087d20cda67f7dee3f8a5a6930751443572232ba9eb859eb00a7d8c22f3e9ac963231bff5551587dc60d484ed72df4a79cdd8be233db2f2aeea687dbbb67f59de2c6c40868c4edb11314b6f358edbdb428190af49e201231695cc371618b7aa720ffaaecc605db97b15b11738a797dd436deee4f71d9da1a8077fc1c324fc087fe69f4fc074c2cdaed054de5b3187608eae6535497053eb2cb69ad29605ba808904ad8ead738393fe6eed3b5f0089897459337fb56b8f71dc10bf2ee83d97cc5b43e7c4e80d3bb2d11b6818fa669584c06af4119b8e0759f909cb3c6f3b098521a528dc5a68b30056756ac2acfb7a3fe3fa5ba2888d427c09ac906020ab158b22a5fb6c1c8cdbaffc3ab8ec266809d78db2fb2b649b28497aaf3a048a97f05fad5a5fd06f119e6d79032f2a057c06e0790b388c921a051287dfc83d59e14d6e8a9221d275ed6f5d88fcc49c05b41df4072faa8fa32dae45e4324754b5f372b881f736319ac7ca07ff1870ffef9d4cc54987a80d7775d055e9ccd597787d9fabfa228e365612e6ea8865fc1786e3a7bda94fb
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109088);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0172", "CVE-2018-0173", "CVE-2018-0174");
  script_bugtraq_id(103545, 103552, 103554);
  script_xref(name:"TRA", value:"TRA-2018-06");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg62730");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg62754");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh91645");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-dhcpr1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-dhcpr2");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-dhcpr3");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS DHCP Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by multiple denial of service
vulnerabilities in the DHCP client implementation when parsing DHCP
packets. An unauthenticated, remote attacker can exploit these issues,
via specially crafted DHCP packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dhcpr1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfe8b7e0");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dhcpr2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2af6e16d");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dhcpr3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?570bb167");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg62730");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg62754");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuh91645");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg62730, CSCvg62754, and CSCuh91645.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0174");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
port = get_kb_item("Host/Cisco/IOS-XE/Port");
if (empty_or_null(port))
  port = 0;

flag = 0;

if (
  ver == "3.2.0JA" ||
  ver == "3.2.0SE" ||
  ver == "3.2.0SG" ||
  ver == "3.2.1SE" ||
  ver == "3.2.1SG" ||
  ver == "3.2.2SE" ||
  ver == "3.2.2SG" ||
  ver == "3.2.3SE" ||
  ver == "3.2.3SG" ||
  ver == "3.2.4SG" ||
  ver == "3.2.5SG" ||
  ver == "3.2.6SG" ||
  ver == "3.2.7SG" ||
  ver == "3.2.8SG" ||
  ver == "3.2.9SG" ||
  ver == "3.2.10SG" ||
  ver == "3.2.11SG" ||
  ver == "3.3.0SE" ||
  ver == "3.3.0SG" ||
  ver == "3.3.0SQ" ||
  ver == "3.3.0XO" ||
  ver == "3.3.1SE" ||
  ver == "3.3.1SG" ||
  ver == "3.3.1SQ" ||
  ver == "3.3.1XO" ||
  ver == "3.3.2SE" ||
  ver == "3.3.2SG" ||
  ver == "3.3.2XO" ||
  ver == "3.3.3SE" ||
  ver == "3.3.4SE" ||
  ver == "3.3.5SE" ||
  ver == "3.4.0SG" ||
  ver == "3.4.0SQ" ||
  ver == "3.4.1SG" ||
  ver == "3.4.1SQ" ||
  ver == "3.4.2SG" ||
  ver == "3.4.3SG" ||
  ver == "3.4.4SG" ||
  ver == "3.4.5SG" ||
  ver == "3.4.6SG" ||
  ver == "3.4.7SG" ||
  ver == "3.4.8SG" ||
  ver == "3.5.0E" ||
  ver == "3.5.0SQ" ||
  ver == "3.5.1E" ||
  ver == "3.5.1SQ" ||
  ver == "3.5.2E" ||
  ver == "3.5.2SQ" ||
  ver == "3.5.3E" ||
  ver == "3.5.3SQ" ||
  ver == "3.5.4SQ" ||
  ver == "3.5.5SQ" ||
  ver == "3.5.6SQ" ||
  ver == "3.5.7SQ" ||
  ver == "3.5.8SQ" ||
  ver == "3.6.0E" ||
  ver == "3.6.0aE" ||
  ver == "3.6.0bE" ||
  ver == "3.6.1E" ||
  ver == "3.6.2E" ||
  ver == "3.6.2aE" ||
  ver == "3.6.3E" ||
  ver == "3.6.4E" ||
  ver == "3.6.5E" ||
  ver == "3.6.5aE" ||
  ver == "3.6.5bE" ||
  ver == "3.6.6E" ||
  ver == "3.6.7E" ||
  ver == "3.6.7aE" ||
  ver == "3.6.7bE" ||
  ver == "3.6.8E" ||
  ver == "3.7.0E" ||
  ver == "3.7.0S" ||
  ver == "3.7.0bS" ||
  ver == "3.7.1E" ||
  ver == "3.7.1S" ||
  ver == "3.7.1aS" ||
  ver == "3.7.2E" ||
  ver == "3.7.2S" ||
  ver == "3.7.2tS" ||
  ver == "3.7.3E" ||
  ver == "3.7.3S" ||
  ver == "3.7.4E" ||
  ver == "3.7.4S" ||
  ver == "3.7.4aS" ||
  ver == "3.7.5E" ||
  ver == "3.7.5S" ||
  ver == "3.7.6S" ||
  ver == "3.7.7S" ||
  ver == "3.7.8S" ||
  ver == "3.8.0E" ||
  ver == "3.8.0S" ||
  ver == "3.8.1E" ||
  ver == "3.8.1S" ||
  ver == "3.8.2E" ||
  ver == "3.8.2S" ||
  ver == "3.8.3E" ||
  ver == "3.8.4E" ||
  ver == "3.8.5E" ||
  ver == "3.8.5aE" ||
  ver == "3.9.0E" ||
  ver == "3.9.0S" ||
  ver == "3.9.0aS" ||
  ver == "3.9.1E" ||
  ver == "3.9.1S" ||
  ver == "3.9.1aS" ||
  ver == "3.9.2E" ||
  ver == "3.9.2S" ||
  ver == "3.9.2bE" ||
  ver == "3.10.0E" ||
  ver == "3.10.0S" ||
  ver == "3.10.0cE" ||
  ver == "3.10.1S" ||
  ver == "3.10.2S" ||
  ver == "3.10.2aS" ||
  ver == "3.10.2tS" ||
  ver == "3.10.3S" ||
  ver == "3.10.4S" ||
  ver == "3.10.5S" ||
  ver == "3.10.6S" ||
  ver == "3.10.7S" ||
  ver == "3.10.8S" ||
  ver == "3.10.8aS" ||
  ver == "3.10.9S" ||
  ver == "3.10.10S" ||
  ver == "3.11.0S" ||
  ver == "3.11.1S" ||
  ver == "3.11.2S" ||
  ver == "3.11.3S" ||
  ver == "3.11.4S" ||
  ver == "3.12.0S" ||
  ver == "3.12.0aS" ||
  ver == "3.12.1S" ||
  ver == "3.12.2S" ||
  ver == "3.12.3S" ||
  ver == "3.12.4S" ||
  ver == "3.13.0S" ||
  ver == "3.13.0aS" ||
  ver == "3.13.1S" ||
  ver == "3.13.2S" ||
  ver == "3.13.2aS" ||
  ver == "3.13.3S" ||
  ver == "3.13.4S" ||
  ver == "3.13.5S" ||
  ver == "3.13.5aS" ||
  ver == "3.13.6S" ||
  ver == "3.13.6aS" ||
  ver == "3.13.6bS" ||
  ver == "3.13.7S" ||
  ver == "3.13.7aS" ||
  ver == "3.13.8S" ||
  ver == "3.14.0S" ||
  ver == "3.14.1S" ||
  ver == "3.14.2S" ||
  ver == "3.14.3S" ||
  ver == "3.14.4S" ||
  ver == "3.15.0S" ||
  ver == "3.15.1S" ||
  ver == "3.15.1cS" ||
  ver == "3.15.2S" ||
  ver == "3.15.3S" ||
  ver == "3.15.4S" ||
  ver == "3.16.0S" ||
  ver == "3.16.0aS" ||
  ver == "3.16.0bS" ||
  ver == "3.16.0cS" ||
  ver == "3.16.1S" ||
  ver == "3.16.1aS" ||
  ver == "3.16.2S" ||
  ver == "3.16.2aS" ||
  ver == "3.16.2bS" ||
  ver == "3.16.3S" ||
  ver == "3.16.3aS" ||
  ver == "3.16.4S" ||
  ver == "3.16.4aS" ||
  ver == "3.16.4bS" ||
  ver == "3.16.4cS" ||
  ver == "3.16.4dS" ||
  ver == "3.16.4eS" ||
  ver == "3.16.4gS" ||
  ver == "3.16.5S" ||
  ver == "3.16.5aS" ||
  ver == "3.16.5bS" ||
  ver == "3.16.6S" ||
  ver == "3.16.6bS" ||
  ver == "3.17.0S" ||
  ver == "3.17.1S" ||
  ver == "3.17.1aS" ||
  ver == "3.17.2S " ||
  ver == "3.17.3S" ||
  ver == "3.17.4S" ||
  ver == "3.18.0S" ||
  ver == "3.18.0SP" ||
  ver == "3.18.0aS" ||
  ver == "3.18.1S" ||
  ver == "3.18.1SP" ||
  ver == "3.18.1aSP" ||
  ver == "3.18.1bSP" ||
  ver == "3.18.1cSP" ||
  ver == "3.18.1gSP" ||
  ver == "3.18.1hSP" ||
  ver == "3.18.1iSP" ||
  ver == "3.18.2S" ||
  ver == "3.18.2SP" ||
  ver == "3.18.2aSP" ||
  ver == "3.18.3S" ||
  ver == "3.18.3SP" ||
  ver == "3.18.3aSP" ||
  ver == "3.18.3bSP" ||
  ver == "3.18.4S" ||
  ver == "16.1.1" ||
  ver == "16.1.2" ||
  ver == "16.1.3" ||
  ver == "16.2.1" ||
  ver == "16.2.2" ||
  ver == "16.3.1" ||
  ver == "16.3.1a" ||
  ver == "16.3.2" ||
  ver == "16.3.3" ||
  ver == "16.3.4" ||
  ver == "16.3.5" ||
  ver == "16.3.5b" ||
  ver == "16.4.1" ||
  ver == "16.4.2" ||
  ver == "16.4.3" ||
  ver == "16.5.1" ||
  ver == "16.5.1a" ||
  ver == "16.5.1b" ||
  ver == "16.5.2" ||
  ver == "16.6.1" ||
  ver == "16.6.2" ||
  ver == "16.6.6" ||
  ver == "16.7.1" ||
  ver == "16.7.1a" ||
  ver == "16.7.1b" ||
  ver == "16.7.3" ||
  ver == "16.9.1b" ||
  ver == "16.9.1c" ||
  ver == "16.9.1d" ||
  ver == "16.12.1"
)
{
  flag++;
}

cmds = make_list();
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include ip helper-address", "show running-config | include ip helper-address");
  if (check_cisco_result(buf))
  {
    if (preg(string:buf, pattern:"ip helper-address", multiline:TRUE))
    {
      cmds = make_list(cmds, "show running-config | include ip helper-address");
      buf2 =  cisco_command_kb_item("Host/Cisco/Config/show running-config | include ip dhcp relay information option", "show running-config | include ip dhcp relay information option");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline:TRUE, pattern:"ip dhcp relay information option", string:buf2))
        {
          cmds = make_list(cmds,"show running-config | include ip dhcp relay information option");
          flag = 1;
        }
      }
    }
  }
  else if (cisco_needs_enable(buf))
    override = 1;

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag || override)
{
  security_report_cisco(
    port     : port,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCvg62730, CSCvg62754, CSCuh91645",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
