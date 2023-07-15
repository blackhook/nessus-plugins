#TRUSTED 14ebb8d19855b48778c73820e9feccf13c036d3ed694147e712209d6719824ba7d8bd2974b8c0639cdc7971227e07fd38059d2e2571159edd48ee819b33d33f7b28c1cb4e6154a73fdde70c50a49eb91cc69c10e4ec2f97c96933ed4302c2b79e1973712b2e74f6a90fe2356dd3052ed2b62e32c2324ac07d6ebeb3c8345413ff51ebf5c7819614f43b67a2c7222e1ddfc639d35d1d96a10f1f5d6edc061fd227538a168c8a2f4a53c29eb1b2ec503a59da57178a0036e561bb2fcf3d54f65e1b820047acae2ffd231e9e730c082673202984c0cb31ce6ec39725de81c83c4c72e57cae72299129c0529a371e10ed0a4d65e91737cda53065d46c0811001e2bf1075a2d8bc43cb0deef513cc892753f1ffdf975e3bea613050ddb3e5d1839d4c07ea973ddcb7e8891f48fbd29a91806b8f4f0628de855d63b1073523809061b0ef40db06dc704175f6b63d006217b47ddd5928b592d2899b436c07ab5ef9364ea1d0995527d46ef125a498a23cd25c5db53016542cc474a70a5e17332aa42b99a552063a9649e8c0dfd0c18048dd64d3f8c472f81f5415d3f76d23a25caaf4bfd7c940a7a79da3b208f702fdadae0bec4790fb765d91bf4a9b34dc26ae8681aefcf4917d9d503cf46fd972a2eb234ef4c1129b92d1e2d2b88556fae6d080035aaff0f655c7c39212243863df9c6056ac65d39e48ea275635e31fc023668cfdcc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82589);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0644");
  script_bugtraq_id(73332);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo53622");

  script_name(english:"Cisco IOS XE AppNav Component RCE");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a vulnerability in the AppNav component due to the improper processing
of TCP packets. An unauthenticated, remote attacker, using a crafted
TCP packet, can exploit this to cause a device reload or to execute
arbitrary code in the forwarding engine.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4cbb5bb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuo53622");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0644");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

# Per Bug CSCuo53622
if (
  !(
    "ASR1k"    >< model ||
    "ISR4400"  >< model ||
    "CSR1000V" >< model
  )
) audit(AUDIT_HOST_NOT, "an affected model");

# Bug (converted) and CVRF
if (version == "3.10.2S") flag++;

# CVRF
if (version == "3.8.0S")   flag++;
if (version == "3.8.0S")   flag++;
if (version == "3.8.1S")   flag++;
if (version == "3.8.2S")   flag++;
if (version == "3.9.1S")   flag++;
if (version == "3.9.0S")   flag++;
if (version == "3.10.0S")  flag++;
if (version == "3.10.1S")  flag++;
if (version == "3.10.2S")  flag++;
if (version == "3.10.0aS") flag++;
if (version == "3.11.1S")  flag++;
if (version == "3.12.0S")  flag++;
if (version == "3.11.2S")  flag++;
if (version == "3.9.2S")   flag++;
if (version == "3.11.0S")  flag++;

# Check NAT config
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_service-insertion_appnav-controller-group", "show service-insertion appnav-controller-group");
  if (check_cisco_result(buf))
  {
    if ("All AppNav Controller Groups in service context" >< buf )
    {
      lines = split(buf);
      count = max_index(buf);
      # Find 'Members:' line, followed by
      # two lines of IP addresses.
      for (i=0; i<count-2; i++)
      {
        if (
          lines[i] == "Members:"
          &&
          lines[i+1] =~ "^\d+\.\d+\.\d+\.\d+$"
          &&
          lines[i+2] =~ "^\d+\.\d+\.\d+\.\d+$"
        )
          flag = 1;
      }
    }
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCuo53622' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
