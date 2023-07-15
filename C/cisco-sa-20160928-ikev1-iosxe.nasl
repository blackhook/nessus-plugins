#TRUSTED 4060229c7bf74a53432ae94e8e2076fce950275e7ece8007745d80ada4cdcf04069b1d48d8e64bfb657aaf27954fee62a9f6df86bc0513e1306d01563f497ea20067547e545301226af8b3552aaf769f64d37b2c12d557b620a8b783554d464ea1c0e62fdfc817eacfb5b0c628751ceb2efeb2dd71ab7e47584856a328605a4891761ae2956054bb9edd11556990b829322b8c7f1b7547ff86bb212cbc24ef49b813022fe2ee5853522874c0145ab69af2c85befbd19b0a1c3cdb9d7df1b7bbe330bc2b73b51ec7d6f6797598f1d909e2a4237ab1b18761d9a8ccee98b847395093c74c92ba5b161fdcf469bdbf5df49d91d3a0bd4c693743429dfc38e21e56b630a2e0a85a6cc9db1a9764e52909f7d05854a7521f934f4a95eba591239ff511ac83fe2281fb1f38346c50ecbf7618cec17a3dc86e0af99de7cb2605c2b6ea3c61b716c59a1d3ca78aad52caf6f6b753982e1cda753dcde8d9f4c551528631d5a5020e9f530ec71252fa0af7e8d8b8508c17b56b890ddf4403e0b2bf6012fa72dc8b6c7369ec3594eff1f5c2b35ae88f01b5def7351c0cc803fcc23075cd1184cbcf0552274e23b60457c5aca0d65ab731f372c7b7d7f933f669ac0ee9873c7492531a1cbebb999f5eec751e40a623e6bf0bae786952cdd6c30645e291408d50fcac837f84ad4f186237b7b93a997ae251a0ef8e6951494d7c39f78acde43cf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94763);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-6381");
  script_bugtraq_id(93195);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy47382");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-ios-ikev1");

  script_name(english:"Cisco IOS XE IKEv1 Fragmentation DoS (cisco-sa-20160928-ikev1)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by a denial
of service vulnerability in the Internet Key Exchange version 1
(IKEv1) subsystem due to improper handling of fragmented IKEv1
packets. An unauthenticated, remote attacker can exploit this issue,
via specially crafted IKEv1 packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-ios-ikev1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30c88959");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy47382. Alternatively, as a workaround, IKEv2 fragmentation can be
disabled by using the 'no crypto isakmp fragmentation' command.
However, if IKEv1 fragmentation is needed, there is no workaround that
addresses this vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;
cmds = make_list();

# Check for vuln version
if ( ver == "3.1.0S" ) flag++;
else if ( ver == "3.1.1S" ) flag++;
else if ( ver == "3.1.2S" ) flag++;
else if ( ver == "3.1.3aS" ) flag++;
else if ( ver == "3.1.4aS" ) flag++;
else if ( ver == "3.1.4S" ) flag++;
else if ( ver == "3.2.1S" ) flag++;
else if ( ver == "3.2.2S" ) flag++;
else if ( ver == "3.3.0S" ) flag++;
else if ( ver == "3.3.0SG" ) flag++;
else if ( ver == "3.3.0XO" ) flag++;
else if ( ver == "3.3.1S" ) flag++;
else if ( ver == "3.3.1SG" ) flag++;
else if ( ver == "3.3.1XO" ) flag++;
else if ( ver == "3.3.2S" ) flag++;
else if ( ver == "3.3.2SG" ) flag++;
else if ( ver == "3.4.0aS" ) flag++;
else if ( ver == "3.4.0S" ) flag++;
else if ( ver == "3.4.0SG" ) flag++;
else if ( ver == "3.4.1S" ) flag++;
else if ( ver == "3.4.1SG" ) flag++;
else if ( ver == "3.4.2S" ) flag++;
else if ( ver == "3.4.2SG" ) flag++;
else if ( ver == "3.4.3S" ) flag++;
else if ( ver == "3.4.3SG" ) flag++;
else if ( ver == "3.4.4S" ) flag++;
else if ( ver == "3.4.4SG" ) flag++;
else if ( ver == "3.4.5S" ) flag++;
else if ( ver == "3.4.5SG" ) flag++;
else if ( ver == "3.4.6S" ) flag++;
else if ( ver == "3.4.6SG" ) flag++;
else if ( ver == "3.4.7SG" ) flag++;
else if ( ver == "3.5.0E" ) flag++;
else if ( ver == "3.5.0S" ) flag++;
else if ( ver == "3.5.1E" ) flag++;
else if ( ver == "3.5.1S" ) flag++;
else if ( ver == "3.5.2E" ) flag++;
else if ( ver == "3.5.2S" ) flag++;
else if ( ver == "3.5.3E" ) flag++;
else if ( ver == "3.6.0E" ) flag++;
else if ( ver == "3.6.0S" ) flag++;
else if ( ver == "3.6.1E" ) flag++;
else if ( ver == "3.6.1S" ) flag++;
else if ( ver == "3.6.2aE" ) flag++;
else if ( ver == "3.6.2E" ) flag++;
else if ( ver == "3.6.2S" ) flag++;
else if ( ver == "3.6.3E" ) flag++;
else if ( ver == "3.6.4E" ) flag++;
else if ( ver == "3.7.0E" ) flag++;
else if ( ver == "3.7.0S" ) flag++;
else if ( ver == "3.7.1E" ) flag++;
else if ( ver == "3.7.1S" ) flag++;
else if ( ver == "3.7.2E" ) flag++;
else if ( ver == "3.7.2S" ) flag++;
else if ( ver == "3.7.2tS" ) flag++;
else if ( ver == "3.7.3E" ) flag++;
else if ( ver == "3.7.3S" ) flag++;
else if ( ver == "3.7.4aS" ) flag++;
else if ( ver == "3.7.4S" ) flag++;
else if ( ver == "3.7.5S" ) flag++;
else if ( ver == "3.7.6S" ) flag++;
else if ( ver == "3.7.7S" ) flag++;
else if ( ver == "3.8.0E" ) flag++;
else if ( ver == "3.8.0S" ) flag++;
else if ( ver == "3.8.1E" ) flag++;
else if ( ver == "3.8.1S" ) flag++;
else if ( ver == "3.8.2S" ) flag++;
else if ( ver == "3.9.0aS" ) flag++;
else if ( ver == "3.9.0S" ) flag++;
else if ( ver == "3.9.1aS" ) flag++;
else if ( ver == "3.9.1S" ) flag++;
else if ( ver == "3.9.2S" ) flag++;
else if ( ver == "3.10.0S" ) flag++;
else if ( ver == "3.10.1S" ) flag++;
else if ( ver == "3.10.1xbS" ) flag++;
else if ( ver == "3.10.2S" ) flag++;
else if ( ver == "3.10.3S" ) flag++;
else if ( ver == "3.10.4S" ) flag++;
else if ( ver == "3.10.5S" ) flag++;
else if ( ver == "3.10.6S" ) flag++;
else if ( ver == "3.10.7S" ) flag++;
else if ( ver == "3.11.0S" ) flag++;
else if ( ver == "3.11.1S" ) flag++;
else if ( ver == "3.11.2S" ) flag++;
else if ( ver == "3.11.3S" ) flag++;
else if ( ver == "3.11.4S" ) flag++;
else if ( ver == "3.12.0aS" ) flag++;
else if ( ver == "3.12.0S" ) flag++;
else if ( ver == "3.12.1S" ) flag++;
else if ( ver == "3.12.2S" ) flag++;
else if ( ver == "3.12.3S" ) flag++;
else if ( ver == "3.12.4S" ) flag++;
else if ( ver == "3.13.0aS" ) flag++;
else if ( ver == "3.13.0S" ) flag++;
else if ( ver == "3.13.1S" ) flag++;
else if ( ver == "3.13.2aS" ) flag++;
else if ( ver == "3.13.2S" ) flag++;
else if ( ver == "3.13.3S" ) flag++;
else if ( ver == "3.13.4S" ) flag++;
else if ( ver == "3.13.5S" ) flag++;
else if ( ver == "3.14.0S" ) flag++;
else if ( ver == "3.14.1S" ) flag++;
else if ( ver == "3.14.2S" ) flag++;
else if ( ver == "3.14.3S" ) flag++;
else if ( ver == "3.15.0S" ) flag++;
else if ( ver == "3.15.1cS" ) flag++;
else if ( ver == "3.15.1S" ) flag++;
else if ( ver == "3.15.2S" ) flag++;
else if ( ver == "3.15.3S" ) flag++;
else if ( ver == "3.16.0cS" ) flag++;
else if ( ver == "3.16.0S" ) flag++;
else if ( ver == "3.16.1aS" ) flag++;
else if ( ver == "3.16.1S" ) flag++;
else if ( ver == "3.16.2aS" ) flag++;
else if ( ver == "3.16.2S" ) flag++;
else if ( ver == "3.17.0S" ) flag++;
else if ( ver == "3.17.1S" ) flag++;
else if ( ver == "3.18.0S" ) flag++;
else if ( ver == "16.1.1" ) flag++;
else if ( ver == "16.1.2" ) flag++;

if(!flag)
  audit(AUDIT_INST_VER_NOT_VULN, ver);

# Check that IKEv1 config or IKEv1 is running
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # Check for condition 1, IKEv1 config
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config","show running-config");
  if (check_cisco_result(buf))
  {
    if ( "crypto isakmp fragmentation" >< buf )
    {
      flag = 1;
      cmds = make_list('show running-config');
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # Check for condition 2, IKEv1 is running
  if (flag)
  {
    flag = 0;

    pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|4500)\s";
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
    if (!flag)
    {
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:pat, string:buf))
        {
          flag = 1;
          cmds = make_list(cmds, 'show ip sockets');
        }
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }

    if (!flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:pat, string:buf))
        {
          flag = 1;
          cmds = make_list(cmds, 'show udp');
        }
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : 'CSCuy47382',
    cmds     : cmds
  );
}
else audit(AUDIT_HOST_NOT, "affected");
