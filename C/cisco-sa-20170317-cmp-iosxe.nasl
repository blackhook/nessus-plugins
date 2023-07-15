#TRUSTED 53b4da1b931b4039fa7ce3545bcd29d055b1d0917f9915a12f3d4dab3a00d58f8345d32b914285af243461f5c55bdb400a2f5000f8451f2412f683d7796b6526a6529ec0d35d3cf54da04a1f677cc4288d9a8b490f028ccda5923f66d9d12818c298b5a4e2e484813d57e1666c42c9173b5ddc80e7221b5169e570656f9ee4b0e2ee347168410d067b4af6f611f4212576b44c91f5ed3d207316204ad6dc08b16e1f1309500df73330979dba3008ab995801125539c3e9d19f4dc6ee48af007f61c29e5750b27eaa87884675a272e824b62efca92ca7ba08af4648bf5bd236f7d3bde896a71d3ac57f3e901ae9ebc629cfc762733df42e3bbd55f2ec857d5efc01bb947fb2fab841272b5a15f49ce5dbd63faa9f5609964a1876431f5e6f00f7e895c786d665aed56d4d46130f05aaeac647f26da889fd5e73249075f5516fa0959d75317687bc33c11a429b4d8610c9e3ab36fbe20014ea70a3fd6e4f65119de1964b0929ce2dada5087602889bf411a07d95e0ea3ab7c07dd735e0215a3e46618cb699770cfc8a46b8fdefb4e173e8587f4d2d9d520fffdd00c28e313aa46fdd9fad6d62ee3d7a003530bb6bf9d7c67e8fe690f3f4b8ccf34d86b0b9a058e478fab45aeec0adb35670a26aca88b22fa9b014f8355fbb90c4178c6ceb43eef0a00c664c0e3f3307ecff590c5e57240c2a0e161a311141ff2e03db5f7cc001b5
#TRUST-RSA-SHA256 56853a44a96629228a935bd2b590591879f8e95fa3ef4cfd8d6455e5b0dceb8884229cabc7cc4edba0c1cff7782846e3289915bdc0a48aee2f2c7ec99a006ac9c206c4525eb8051addd42d0b5ea475d57041a39dfea518a4a8fb943f6a5f27ed33dcb90a619ee631850526426bb706139bbb151e49bbbb0e424be3cba3afb2735ab4bb2e62250682f6a8310b0e964f9a30b089c4ebe762484b8aaa03b32be6a9a96078e69858fa40859b04a0fb11ff4f5a119f5d90d3a3bb48390c21f40168ab84ba89adb8ac0974587f629ee65e54df1ffffce164ba10ae2e04345ee5256bc9b4b1a83ddf21a40712608dc4cf141f537fc069e206a1efedcaa5aae1e8f74abf057c88df131b18cbce282016b178179d1c4253052502705b82f969c0883bb9c6b56b91ed77a1299a8ae21994349e1d806d5a17e276134561fd50b61e62e4023fb05b2be43bf5bf50b5a2819f1effed7b4376185c754d1af083e9f740db8f1272992ae32398889094112232d0744cdccaef81970f40025d04106b055cfdb421c9bdb60bb97b1ef7f9dbb1f3c14f17723d9f97aed03eeebea15a55c90e6061598eca47cd2379f5b6d3624139c75841160dc00783f39eb17d34f330e10764976b2bf5c7abb74ebbcc3fb055b21883c3c3ed306b284ca9bce9203dddc4cf4b464586a207a785126672d4fec9915986e661c42ad4f0dc746f280e0686584820cafaa7
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97992);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-3881");
  script_bugtraq_id(96960);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd48893");
  script_xref(name:"IAVA", value:"2017-A-0073");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170317-cmp");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Cisco IOS XE Cluster Management Protocol Telnet Option Handling RCE (cisco-sa-20170317-cmp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by a remote
code execution vulnerability in the Cluster Management Protocol (CMP)
subsystem due to improper handling of CMP-specific Telnet options. An
unauthenticated, remote attacker can exploit this by establishing a
Telnet session with malformed CMP-specific telnet options, to execute
arbitrary code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cb68237");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvd48893. Alternatively, as a workaround, disable the Telnet
protocol for incoming connections.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3881");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
cmds = make_list();

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Check for vuln version
# these were extracted from the CVRF
if (
  ver == "2.2.0" ||
  ver == "2.2.1" ||
  ver == "2.2.2" ||
  ver == "2.2.3" ||
  ver == "2.3.0" ||
  ver == "2.3.1" ||
  ver == "2.3.1t" ||
  ver == "2.3.2" ||
  ver == "2.4.0" ||
  ver == "2.4.1" ||
  ver == "2.4.2" ||
  ver == "2.4.3" ||
  ver == "2.5.0" ||
  ver == "2.5.1" ||
  ver == "2.6.0" ||
  ver == "2.6.1" ||
  ver == "3.1.0SG" ||
  ver == "3.1.1SG" ||
  ver == "3.2.0SG" ||
  ver == "3.2.0XO" ||
  ver == "3.2.10SG" ||
  ver == "3.2.11SG" ||
  ver == "3.2.2SG" ||
  ver == "3.2.3SG" ||
  ver == "3.2.4SG" ||
  ver == "3.2.5SG" ||
  ver == "3.2.6SG" ||
  ver == "3.2.7SG" ||
  ver == "3.2.8SG" ||
  ver == "3.2.9SG" ||
  ver == "3.3.0SG" ||
  ver == "3.3.0SQ" ||
  ver == "3.3.0XO" ||
  ver == "3.3.1SG" ||
  ver == "3.3.1SQ" ||
  ver == "3.3.1XO" ||
  ver == "3.3.2SG" ||
  ver == "3.3.2XO" ||
  ver == "3.4.0SG" ||
  ver == "3.4.0SQ" ||
  ver == "3.4.1SG" ||
  ver == "3.4.1SQ" ||
  ver == "3.4.2SG" ||
  ver == "3.4.3SG" ||
  ver == "3.4.4SG" ||
  ver == "3.4.5SG" ||
  ver == "3.4.6SG" ||
  ver == "3.4.7aSG" ||
  ver == "3.4.7SG" ||
  ver == "3.4.8SG" ||
  ver == "3.4.9SG" ||
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
  ver == "3.6.0E" ||
  ver == "3.6.1E" ||
  ver == "3.6.2E" ||
  ver == "3.6.3E" ||
  ver == "3.6.4E" ||
  ver == "3.6.5aE" ||
  ver == "3.6.5bE" ||
  ver == "3.6.5E" ||
  ver == "3.6.6E" ||
  ver == "3.7.0E" ||
  ver == "3.7.1E" ||
  ver == "3.7.2E" ||
  ver == "3.7.3E" ||
  ver == "3.7.4E" ||
  ver == "3.8.0E" ||
  ver == "3.8.0EX" ||
  ver == "3.8.1E" ||
  ver == "3.8.2E" ||
  ver == "3.8.3E" ||
  ver == "3.9.0E" ||
  ver == "3.9.1E"
)
  flag++;

if(!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", ver);

# Check if the CMP subsystem is present, then
# Check that device is configured to accept incoming Telnet connections
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # CMP subsystem check
  command = "show subsys class protocol | include ^cmp";
  command_kb = "Host/Cisco/Config/" + command;
  buf = cisco_command_kb_item(command_kb, command);
  if (check_cisco_result(buf))
  {
    if (!preg(string:buf, pattern:"^cmp\s+Protocol", multiline:TRUE))
    {
      # cmp subsystem is not present, so we can audit out as the
      # device is not vuln
      audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", ver + " without the CMP subsystem");
    }
    # otherwise the CMP subsystem is present so we continue on to check
    # if incoming telnet is enabled
    cmds = make_list(cmds, command);
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # check that the device is configured to accept incoming Telnet connections
  # from the advisory
  command = "show running-config | include ^line vty|transport input";
  command_kb = "Host/Cisco/Config/" + command;
  buf = cisco_command_kb_item(command_kb, command);
  if (check_cisco_result(buf))
  {
    # if transport input lists "all" or "telnet", we are vuln
    # otherwise, if there is a "line vty" that is not followed by a
    # transport input line, we are vuln
    # otherwise, we are not vuln
    if (preg(string:buf, pattern:"^\s+transport input.*(all|telnet).*", multiline:TRUE))
    {
      flag = 1;
      cmds = make_list(cmds, command);
    }
    else
    {
      lines = split(buf, keep:FALSE);
      for (i = 0; i < max_index(lines); i++)
      {
        line = lines[i];
        if ((i+1) >= max_index(lines))
          next_line = "";
        else
          next_line = lines[i+1];

        if (line =~ "^line vty" && next_line !~ "^\s+transport input")
        {
          flag = 1;
          cmds = make_list(cmds, command);
          break;
        }
      }
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # no CMP subsystem, no telnet enabled = not vuln
  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : 'CSCvd48893',
    cmds     : cmds
  );
}
else audit(AUDIT_HOST_NOT, "affected");
