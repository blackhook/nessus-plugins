#TRUSTED 34a47aeaa26d89c9194dbaaba53106c0d5af11cbdc537e43711d448818eb2cca91c83f93f0154cd4913d10d1bbc9cab9cfd9ca295f5cdb7475eaae685feac3e4d57a2b5e2c8751bb6d7b5803012d1a856694387745c5202551abb8796444f26d8991d6445417822e4c05e915ee6ecc5c5dd63063dd4cd1b50ff64e56dbd9b776ca4e2218ab7a4d680d9ea59fb3f9b2accf3362371dca4dc36c24ba866726d9daa049a60eb6b69ba1217469ed17bf133ae5abfb1f40f41db07c6e6dc1e526dc319e28d7e35cb9b8e9c733920b758ff417c4e5ba8f8ef53b411ae787b599723fa7ba82e03941c21e91600e7f6b5b0d4ed728b869bb1c964512aaa701cf6d080adacc0f116839e401a472a98b5bcf09c92831576b18c3d95ab3a232bd2b8aa3d88453cdf09349e5cd78f44d36c35cf8efaeaf4ecf03fcdf599d3f24b604c9fd775a657bc1af197d5ade466136459d699ec767d098324e041ab933e949800bf898242efe655569b69d475b69f35c4cd86186226d0c0f68acaa9af76a59b1b2cbeab39885fa925b23cf90394bd8714d63a4896d97e7bd935ba6fa845fbb7fcaf1faa5ce5a0dbdc9511ea66e6b6a875a1516301730d7ee7470c9ddb1067fc6377938d77711de13af7d07e810a77a8d1c92bd34d4401992af862e73e35150b4a5756bb0f2b942c3aff96ec4b3423523889ab99ba1a271eb4e5ba61a7042890de3d08ef6
#TRUST-RSA-SHA256 98a3ab731ef200b26ace203ed1c4dd6191566d6ac6b59465c4fb1fa4e3b28d39241f8fb5a268792b944faba83f14d46d7534116a22d9524082e4ffd45eb36e15762871877c13babb35b974431b412391b05f5b037d1203ca9a1bacfa4549e6237cc49821c63e94a3fe5857324804b7f4ebb29763705cea15494313a5096b6b6c0414d98020fd2c3ebc74a25734afe0035dd60010100bfeab7c35e907fb96e4208d94cb3b669ed03ad63a32d3b2f42c0912a646ee9eef1cf3825e2e50ca0dae7e78a70a143ea784ea47b7b8c915dc6d35a39fff1ab35a10de26f9d2370b07ba1ace82f94b07f7a7cd8f04af25cbb29728eaa7727a365515e6141ae865917f8f06f951a8c307f8b55418b3deb1b0f576d7e640d4f4dc46fbd48255ff23965b9221bd7d313a119c0834375620ca56188ea2174b4fd093162e6109e46f7f371aeeac19f43308b2110af192e4f42cd229887791fd090c940923875500d64e7077c938df78cb7269e85fddf52370640e726ca122d38d51e5d7dcfc2b60a2aee03cd81f0b97223d542370ae9ddb53cc0ba92b5d5f2f64d1ea821c1a63dbb017907beb15a6622d295f4640d6d7ffda27ef0c0e72f28150711605bff47db3d6a34916c8792e4f21e6bf1ba0516ede5ffc8d39b5650a4030cf33b7e28a754dcd5ae7f97ad8baeee922a13d3d8729464f247b5dd56f6e3c322e3fee7a7bf805ed8c9572d484
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101269);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2017-6736",
    "CVE-2017-6737",
    "CVE-2017-6738",
    "CVE-2017-6739",
    "CVE-2017-6740",
    "CVE-2017-6741",
    "CVE-2017-6742",
    "CVE-2017-6743",
    "CVE-2017-6744"
  );
  script_bugtraq_id(99345);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve54313");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve57697");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve60276");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve60376");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve60402");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve60507");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve66540");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve66601");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve66658");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve78027");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve89865");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170629-snmp");
  script_xref(name:"IAVA", value:"2017-A-0191-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/10");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Cisco IOS XE SNMP Packet Handling Remote Buffer Overflow Multiple RCE (cisco-sa-20170629-snmp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by multiple
remote code execution vulnerabilities in the Simple Network Management
Protocol (SNMP) subsystem due to multiple buffer overflow conditions.
An unauthenticated, remote attacker can exploit these vulnerabilities,
via a specially crafted SNMP packet, to execute arbitrary code.

To exploit these vulnerabilities via SNMP version 2c or earlier, the
attacker must know the SNMP read-only community string for the
affected system. To exploit these vulnerabilities via SNMP version 3,
the attacker must have user credentials for the affected system.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170629-snmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?564e08f8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve54313");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve57697");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve60276");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve60376");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve60402");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve60507");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve66540");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve66601");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve66658");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve78027");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve89865");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20170629-snmp. Alternatively, as a workaround,
disable the following MIBs on the device :

  - ADSL-LINE-MIB
  - ALPS-MIB
  - CISCO-ADSL-DMT-LINE-MIB
  - CISCO-BSTUN-MIB
  - CISCO-MAC-AUTH-BYPASS-MIB
  - CISCO-SLB-EXT-MIB
  - CISCO-VOICE-DNIS-MIB
  - CISCO-VOICE-NUMBER-EXPANSION-MIB
  - TN3270E-RT-MIB");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6744");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Check for vuln versions
if (
  ver == '2.2.0' ||
  ver == '2.2.1' ||
  ver == '2.2.2' ||
  ver == '2.2.3' ||
  ver == '2.3.0' ||
  ver == '2.3.1' ||
  ver == '2.3.1t' ||
  ver == '2.3.2' ||
  ver == '2.4.0' ||
  ver == '2.4.1' ||
  ver == '2.4.2' ||
  ver == '2.4.3' ||
  ver == '2.5.0' ||
  ver == '2.5.1' ||
  ver == '2.6.0' ||
  ver == '2.6.1' ||
  ver == '3.1.0S' ||
  ver == '3.1.1S' ||
  ver == '3.1.2S' ||
  ver == '3.1.3aS' ||
  ver == '3.1.4S' ||
  ver == '3.1.4aS' ||
  ver == '3.10.0S' ||
  ver == '3.10.1S' ||
  ver == '3.10.1xbS' ||
  ver == '3.10.2S' ||
  ver == '3.10.2tS' ||
  ver == '3.10.3S' ||
  ver == '3.10.4S' ||
  ver == '3.10.5S' ||
  ver == '3.10.6S' ||
  ver == '3.10.7S' ||
  ver == '3.10.8S' ||
  ver == '3.10.8aS' ||
  ver == '3.11.0S' ||
  ver == '3.11.1S' ||
  ver == '3.11.2S' ||
  ver == '3.11.3S' ||
  ver == '3.11.4S' ||
  ver == '3.12.0S' ||
  ver == '3.12.1S' ||
  ver == '3.12.2S' ||
  ver == '3.12.3S' ||
  ver == '3.12.4S' ||
  ver == '3.13.0S' ||
  ver == '3.13.0aS' ||
  ver == '3.13.1S' ||
  ver == '3.13.2S' ||
  ver == '3.13.3S' ||
  ver == '3.13.4S' ||
  ver == '3.13.5S' ||
  ver == '3.13.6S' ||
  ver == '3.13.6aS' ||
  ver == '3.14.0S' ||
  ver == '3.14.1S' ||
  ver == '3.14.2S' ||
  ver == '3.14.3S' ||
  ver == '3.14.4S' ||
  ver == '3.15.0S' ||
  ver == '3.15.1S' ||
  ver == '3.15.1cS' ||
  ver == '3.15.2S' ||
  ver == '3.15.3S' ||
  ver == '3.15.4S' ||
  ver == '3.16.0S' ||
  ver == '3.16.0cS' ||
  ver == '3.16.1S' ||
  ver == '3.16.2S' ||
  ver == '3.16.3S' ||
  ver == '3.16.4S' ||
  ver == '3.16.4bS' ||
  ver == '3.16.5S' ||
  ver == '3.17.0S' ||
  ver == '3.17.1S' ||
  ver == '3.2.0S' ||
  ver == '3.2.0SE' ||
  ver == '3.2.1S' ||
  ver == '3.2.2S' ||
  ver == '3.3.0S' ||
  ver == '3.3.0SE' ||
  ver == '3.3.1S' ||
  ver == '3.3.2S' ||
  ver == '3.4.0S' ||
  ver == '3.4.0aS' ||
  ver == '3.4.1S' ||
  ver == '3.4.2S' ||
  ver == '3.4.3S' ||
  ver == '3.4.4S' ||
  ver == '3.4.5S' ||
  ver == '3.4.6S' ||
  ver == '3.5.0S' ||
  ver == '3.5.1S' ||
  ver == '3.5.2S' ||
  ver == '3.6.0S' ||
  ver == '3.6.1S' ||
  ver == '3.6.2S' ||
  ver == '3.7.0S' ||
  ver == '3.7.1S' ||
  ver == '3.7.2S' ||
  ver == '3.7.3S' ||
  ver == '3.7.4S' ||
  ver == '3.7.4aS' ||
  ver == '3.7.5S' ||
  ver == '3.7.6S' ||
  ver == '3.7.7S' ||
  ver == '3.8.0EX' ||
  ver == '3.8.0S' ||
  ver == '3.8.1S' ||
  ver == '3.8.2S' ||
  ver == '3.8.5E' ||
  ver == '3.9.0S' ||
  ver == '3.9.1S' ||
  ver == '3.9.2S'
) flag++;

# Check that device is configured with SNMP support
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_snmp_mib", "show snmp mib");
  if (check_cisco_result(buf))
  {
    # "Not all of the MIBs will be displayed in the output of the show
    # snmp mib command but may still be enabled. Customers are advised
    # to implement the entire exclude list as detailed in the
    # Workarounds section of the advisory.""
    if (preg(multiline:TRUE, pattern:"(ADSL-LINE|ALPS|CISCO-ADSL-DMT-LINE|CISCO-BSTUN|CISCO-MAC-AUTH-BYPASS|CISCO-SLB-EXT|CISCO-VOICE-DNIS|CISCO-VOICE-NUMBER-EXPANSION|TN3270E-RT)-MIB", string:buf))
    {
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCve54313, CSCve57697, CSCve60276, CSCve60376, CSCve60402, CSCve60507, CSCve66540, CSCve66601, CSCve66658, CSCve78027, CSCve89865",
    cmds     : make_list("show snmp mib")
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
