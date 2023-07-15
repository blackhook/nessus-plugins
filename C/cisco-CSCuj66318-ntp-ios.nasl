#TRUSTED a090588c6bdbc82ba70939a3eaef764115fba25c20d93e9e5c813e8cdaf994ce94045fc09cf793078dfb4ff68be0f2a6e87f30db350e2f75446ba62ab997d2b2e3a354837e5a6382c5df3815d13318eb451bce95a3e78a15414bc83a93ccf772c3c528aa1349d932fc2698490281d231ff1c2fe717e12d977a021abbc252f9648eca2e483798e19418f1385c5827bf8e233a8afa733a200c46a1468d6f44d29f2f9cc20da7b03f158ba164c7920650996ec671232926772fef5a8b0f0d54b09697e441a3694ecdae648448649856939b97d16dc86b23e6ddbfa39262beeea105d719e4cd99c48ed3f321d8bbc8e6c71fd8445f824b6890634c77934f2411da1d9a236eb7db13782eee881774df9cb158d5a078838342fd507343a156f98ac624e0e0560a8e39e78b940b8da7772087a597dadc7606d3bdba318a2ba479374af4b7b625932f9b3fe9a16b830a4d949132cbe332c750713dc2525b6b4b69dedcf7528e50c440f5a7824052bf65a1cd057ba460535a587f26a221b046338701e9977d87c1b811c7157c7c85185a6574b70ea0562a4d25f501aa1e2be07b05ae64016d80c1087c3bda130396639ea425972367841dafe796f9642f70d426e3a73c5a5ff4f373041b736f9d83bf771286e1fc1c3dc29d89669e215f889caab8409d3b5d7568e204682492995dc581b7d01f33b46b91245cbf9d996d5e3872eec9499e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77052);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3309");
  script_bugtraq_id(68463);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj66318");

  script_name(english:"Cisco IOS NTP Information Disclosure (CSCuj66318)");
  script_summary(english:"Checks IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device potentially contains an issue with the 'ntp
access-group' which could allow a remote attacker to bypass the NTP
access group and query an NTP server configured to deny-all requests.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34884
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d368fe89");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuj66318.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# Per the advisory, IOS affected:
# 15.2M
# 15.2(4)M
# 15.4T
# 15.4(1)T
# Mappings were also added from IOS XE
# No specific hardware conditions
# No workarounds
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
flag = 0;
if (
  version =~ "^15\.2\(1\)S[1-2]?$" || #IOS-XE Mapping for 3.5S  .0, .1, .2
  version =~ "^15\.2\(2\)S[1-2]?$" || #IOS-XE Mapping for 3.6S  .0, .1, .2
  version =~ "^15\.2\(4\)S[1-4]?$" || #IOS-XE Mapping for 3.7S  .0, .1, .2, .3, .4
  version =~ "^15\.3\(1\)S[1-2]?$" || #IOS-XE Mapping for 3.8S  .0, .1, .2
  version =~ "^15\.3\(2\)S1?$"     || #IOS-XE Mapping for 3.9S  .0, .1
  version =~ "^15\.3\(3\)S[1-2]?$" || #IOS-XE Mapping for 3.10S .0, .1, .2
  version == "15.3(3)S0a"          || #IOS-XE Mapping for 3.10.0aS
  version =~ "^15\.4\(1\)S[1-2]$"  || #IOS-XE Mapping for 3.11  .1, .2
  version == "15.2M"               ||
  version == "15.2(4)M"            ||
  version == "15.4T"               ||
  version == "15.4(1)T"
) flag++;

override = 0;
if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  # Check if NTP actually enabled
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      "ntp master" >< buf           ||
      "ntp peer" >< buf             ||
      "ntp broadcast client" >< buf ||
      "ntp multicast client" >< buf
    ) flag++;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco Bug ID      : CSCuj66318' +
    '\n  Installed release : ' + version +
    '\n';
    security_warning(port:0, extra:report+cisco_caveat(override));
  }
  else security_warning(port:0);
}
else audit(AUDIT_HOST_NOT, "affected");
