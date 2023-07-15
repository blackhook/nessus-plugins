#TRUSTED 35fe35332675a2c18478461aeb589eb9142e992ebd6543dec71f1440edc68d4c6c219f7d2871db2a5d8ae6b455d74742e1ec0709ae975304832e620ad264113ae9cc8fcdaa611efba97a430176981d98d8fd8c15213057f83acb75f0ceaaee34a90ab88434b690ae9523d6f4ac7633f397d7b9f93f08940da001d87a434a312298a4f1c3845df041852880813c0fc85763a2a625a0403744af70fd9966432ea81e1013d49038890ca1df68d40adc099bcdebe1869ae21d25bf1d8b3fbf084a9a2c12e150392df0d07b97a6977d6693b5ee03fcecf6d3764251d153b6dc7271803b4f585da442e9dd9d78c6bc6130b5ebeedbbf456bde79c379a66c622159360caade907e687e5bf28fcaddfd95c3836ec37324959ff55220ab8a833e5b4fb950e6a8744d35593d756f9adfc579249a2a12a5cb9061d9a904c7ec129ff815420bb146da07058555bf280f853ad8f40fc39b43b32214f3a417695d7ad76696bbbf50fd5630bafe1d5249b09bf552a056b1ba09617189d81cfa08e2a5b14bf9c8c1eadf5b19491a78d82c34c1922cbe673389ed14713dc1d13d2991020fc3d410a194ea5bade58f3a5387d48e72066faf63cba1159d9e8242e184e91936431e1a4b3beedd4cd51675379fe890549a32917e01301701cc11be84f0635a63f38175cf50e1349789a6d1a6138c9cf7b219ec6105b6f821bcc3be455c9762f93955c25f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93898);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-6382", "CVE-2016-6392");
  script_bugtraq_id(93211);
  script_xref(name:"CISCO-BUG-ID", value:"CSCud36767");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy16399");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-msdp");

  script_name(english:"Cisco IOS XE Multicast Routing Multiple DoS (cisco-sa-20160928-msdp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Cisco IOS XE device is affected by multiple denial of service
vulnerabilities :

  - A denial of service vulnerability exists due to improper
    validation of packets encapsulated in a PIM register
    message. An unauthenticated, remote attacker can exploit
    this, by sending an IPv6 PIM register packet to a PIM
    rendezvous point (RP), to cause the device to restart.
    (CVE-2016-6382)

  - A denial of service vulnerability exists in the IPv4
    Multicast Source Discovery Protocol (MSDP)
    implementation due to improper validation of
    Source-Active (SA) messages received from a configured
    MSDP peer. An unauthenticated, remote attacker can
    exploit this to cause the device to restart.
    (CVE-2016-6392)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-msdp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72b1793a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCud36767");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy16399");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20160928-msdp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/07");

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

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

if (version == "3.2.0JA") flag = 1;
else if (version == "3.8.0E") flag = 1;
else if (version == "3.8.1E") flag = 1;
else if (version == "3.1.3aS") flag = 1;
else if (version == "3.1.0S") flag = 1;
else if (version == "3.1.1S") flag = 1;
else if (version == "3.1.2S") flag = 1;
else if (version == "3.1.4S") flag = 1;
else if (version == "3.1.4aS") flag = 1;
else if (version == "3.2.1S") flag = 1;
else if (version == "3.2.2S") flag = 1;
else if (version == "3.2.0SE") flag = 1;
else if (version == "3.2.1SE") flag = 1;
else if (version == "3.2.2SE") flag = 1;
else if (version == "3.2.3SE") flag = 1;
else if (version == "3.3.0S") flag = 1;
else if (version == "3.3.1S") flag = 1;
else if (version == "3.3.2S") flag = 1;
else if (version == "3.3.0SE") flag = 1;
else if (version == "3.3.1SE") flag = 1;
else if (version == "3.3.2SE") flag = 1;
else if (version == "3.3.3SE") flag = 1;
else if (version == "3.3.4SE") flag = 1;
else if (version == "3.3.5SE") flag = 1;
else if (version == "3.3.0SG") flag = 1;
else if (version == "3.3.1SG") flag = 1;
else if (version == "3.3.2SG") flag = 1;
else if (version == "3.3.0XO") flag = 1;
else if (version == "3.3.1XO") flag = 1;
else if (version == "3.3.2XO") flag = 1;
else if (version == "3.4.0S") flag = 1;
else if (version == "3.4.0aS") flag = 1;
else if (version == "3.4.1S") flag = 1;
else if (version == "3.4.2S") flag = 1;
else if (version == "3.4.3S") flag = 1;
else if (version == "3.4.4S") flag = 1;
else if (version == "3.4.5S") flag = 1;
else if (version == "3.4.6S") flag = 1;
else if (version == "3.4.0SG") flag = 1;
else if (version == "3.4.1SG") flag = 1;
else if (version == "3.4.2SG") flag = 1;
else if (version == "3.4.3SG") flag = 1;
else if (version == "3.4.4SG") flag = 1;
else if (version == "3.4.5SG") flag = 1;
else if (version == "3.4.6SG") flag = 1;
else if (version == "3.4.7SG") flag = 1;
else if (version == "3.5.0E") flag = 1;
else if (version == "3.5.1E") flag = 1;
else if (version == "3.5.2E") flag = 1;
else if (version == "3.5.3E") flag = 1;
else if (version == "3.5.0S") flag = 1;
else if (version == "3.5.1S") flag = 1;
else if (version == "3.5.2S") flag = 1;
else if (version == "3.6.4E") flag = 1;
else if (version == "3.6.0E") flag = 1;
else if (version == "3.6.1E") flag = 1;
else if (version == "3.6.2aE") flag = 1;
else if (version == "3.6.2E") flag = 1;
else if (version == "3.6.3E") flag = 1;
else if (version == "3.6.0S") flag = 1;
else if (version == "3.6.1S") flag = 1;
else if (version == "3.6.2S") flag = 1;
else if (version == "3.7.3E") flag = 1;
else if (version == "3.7.0E") flag = 1;
else if (version == "3.7.1E") flag = 1;
else if (version == "3.7.2E") flag = 1;
else if (version == "3.7.0S") flag = 1;
else if (version == "3.7.1S") flag = 1;
else if (version == "3.7.2S") flag = 1;
else if (version == "3.7.2tS") flag = 1;
else if (version == "3.7.3S") flag = 1;
else if (version == "3.7.4S") flag = 1;
else if (version == "3.7.4aS") flag = 1;
else if (version == "3.7.5S") flag = 1;
else if (version == "3.7.6S") flag = 1;
else if (version == "3.7.7S") flag = 1;
else if (version == "3.8.0S") flag = 1;
else if (version == "3.8.1S") flag = 1;
else if (version == "3.8.2S") flag = 1;
else if (version == "3.9.0S") flag = 1;
else if (version == "3.9.0aS") flag = 1;
else if (version == "3.9.1S") flag = 1;
else if (version == "3.9.1aS") flag = 1;
else if (version == "3.9.2S") flag = 1;
else if (version == "3.10.0S") flag = 1;
else if (version == "3.10.1S") flag = 1;
else if (version == "3.10.1xbS") flag = 1;
else if (version == "3.10.2S") flag = 1;
else if (version == "3.10.2tS") flag = 1;
else if (version == "3.10.3S") flag = 1;
else if (version == "3.10.4S") flag = 1;
else if (version == "3.10.5S") flag = 1;
else if (version == "3.10.6S") flag = 1;
else if (version == "3.10.7S") flag = 1;
else if (version == "3.11.0S") flag = 1;
else if (version == "3.11.1S") flag = 1;
else if (version == "3.11.2S") flag = 1;
else if (version == "3.11.3S") flag = 1;
else if (version == "3.11.4S") flag = 1;
else if (version == "3.12.0S") flag = 1;
else if (version == "3.12.0aS") flag = 1;
else if (version == "3.12.1S") flag = 1;
else if (version == "3.12.4S") flag = 1;
else if (version == "3.12.2S") flag = 1;
else if (version == "3.12.3S") flag = 1;
else if (version == "3.13.2aS") flag = 1;
else if (version == "3.13.5aS") flag = 1;
else if (version == "3.13.5S") flag = 1;
else if (version == "3.13.0S") flag = 1;
else if (version == "3.13.0aS") flag = 1;
else if (version == "3.13.1S") flag = 1;
else if (version == "3.13.2S") flag = 1;
else if (version == "3.13.3S") flag = 1;
else if (version == "3.13.4S") flag = 1;
else if (version == "3.14.0S") flag = 1;
else if (version == "3.14.1S") flag = 1;
else if (version == "3.14.2S") flag = 1;
else if (version == "3.14.3S") flag = 1;
else if (version == "3.15.1cS") flag = 1;
else if (version == "3.15.0S") flag = 1;
else if (version == "3.15.1S") flag = 1;
else if (version == "3.15.2S") flag = 1;
else if (version == "3.17.1aS") flag = 1;
else if (version == "3.17.0S") flag = 1;
else if (version == "3.17.1S") flag = 1;
else if (version == "16.1.1") flag = 1;
else if (version == "16.1.2") flag = 1;
else if (version == "3.16.2bS") flag = 1;
else if (version == "3.16.0S") flag = 1;
else if (version == "3.16.0cS") flag = 1;
else if (version == "3.16.1S") flag = 1;
else if (version == "3.16.1aS") flag = 1;
else if (version == "3.16.2S") flag = 1;
else if (version == "3.16.2aS") flag = 1;

cmds = make_list();
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config | include ip msdp peer", "show running-config | include ip msdp peer");
    if (check_cisco_result(buf))
    {
      # Vulnerable if msdp enabled
      if (preg(pattern:"\s*ip\s*msdp\s*peer\s*[0-9]{1,3}(\.[0-9]{1,3}){3}", multiline:TRUE, string:buf))
      {
        flag = 1;
        cmds = make_list(cmds, "show running-config | include ip msdp peer");
      }

      buf2 = cisco_command_kb_item("Host/Cisco/Config/show_running-config | include include ipv6 multicast-routing", "show running-config | include ipv6 multicast-routing");
      if (check_cisco_result(buf2))
      {
        # Vulnerable if ipv6 multicast routing enabled
        if (preg(pattern:"\s*ipv6\s*multicast-routing", multiline:TRUE, string:buf))
        {
          flag = 1;
          cmds = make_list(cmds, "show running-config | include ipv6 multicast-routing");
        }
      }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : "CSCud36767, CSCuy16399",
    cmds     : cmds
  );
}
else audit(AUDIT_HOST_NOT, "affected");
