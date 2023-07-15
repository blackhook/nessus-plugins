#TRUSTED 669295228f48796de2386672109131a16bdd4ca29eb6cd34ca4c139a05444822e51f210ab5bf650ae0dfe78583b2622572aa275d23dc4c00cdfc3e2c67e74d55452394eebade0915d1addc130cc86aea542e268fc62b73d54d38dc4334be318b6767e7141db512d2ad2b5cb0a3c7e8a8e066ed2d62d48d92fad0a238038e3a0f8a99860431c2f64495c4891023eb14461b8208fd326b024d8ac1d2ee09a05a80665cfe9c1cbcff191c3cb8e18382faaaf936fc25955f842d3fb7c2b58d1bf78b3eb44d14ae1e842e7aa67ad74199778ef8783dc549436df4ac6b96cd43b95034618dd96083c86436c22ba55ef10c3331d7044878e3d2844caa84cada9aa4946811606eca342ef9d615fd9c254b5f87b4d70e95dd73e9ad131ae055ea4ffefe67ed4d917f48c8719c411caed2d534276cb98eb9aeff21948af5ca3e554049dfb6669c224860e3966eb84ea00ad09328c636e6a0b464b51bbd387f0bcb664f84f591a12d62cd008705312d3e93698b1bf5a48d30984b4ce1f5a2b02e300cdde2124b448a12228c5cfaf30b0e076c2d5f813a5b5b2db41b99b98b24c301a07041244b3ec48324481d3c586ca1c5a0233e9f2491cc59769892ab0fb6a2b33dfd6381c5e381b3fbac2a229bfa1ff007cedc001c934e58bd61c0147b8f5736c09299f8174b0f1f597bc567468f04f04b675502b3acbafb9f8cfc848301505365e88779
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77222);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2014-3321");
  script_bugtraq_id(68536);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo91149");

  script_name(english:"Cisco IOS XR MPLS and Network Processor (NP) Chip DoS (Typhoon-based Line Cards)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version Cisco IOS XR software
that is potentially affected by a denial of service vulnerability
related the handling of maliciously crafted MPLS (Multiprotocol Label
Switching) packets routed by a bridge-group virtual interface.

Note that this issue only affects Cisco ASR 9000 series devices using
Typhoon-based line cards and MPLS.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34936");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34936
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f173fd3e");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuo91149");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco bug ID CSCuo91149.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3321");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2014-2021 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version",  "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# This requires a very specific and non-supported
# configuration to make the device vulnerable
# which is why this is a paranoid check
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Check version
# Affected list from vendor:
# 4.3.0/1/2 and 4.3.4.MPLS
version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if (version !~ "^4\.3\.[0124]($|[^0-9])")
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XR", version);

# Check model
model = get_kb_item("CISCO/model");
if(model && model !~ "ciscoASR9[0-9]{3}") audit(AUDIT_HOST_NOT, "ASR 9000 series");
# First source failed, try another source
if(!model)
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("ASR9K" >!< model) audit(AUDIT_HOST_NOT, "ASR 9000 series");
}

# Example output from 'show mpls interfaces'
#Interface              IP         Tunnel   Operational
#Ethernet1/1/1          Yes (tdp)  No       No
#Ethernet1/1/2          Yes (tdp)  Yes      No
#Ethernet1/1/3          Yes (tdp)  Yes      Yes
#POS2/0/0               Yes (tdp)  No       No
#ATM0/0.1               Yes (tdp)  No       No          (ATM labels)
#ATM3/0.1               Yes (ldp)  No       Yes         (ATM labels)
#ATM0/0.2               Yes (tdp)  No       Yes

override = FALSE;

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_mpls_interfaces", "show mpls interfaces");
  if (check_cisco_result(buf))
  {
    # Check if we have an operational MPLS interface, audit out if we don't
    if(
      buf !~ "^Interface\s+IP\s+Tunnel\s+Operational" || # Does buf have the right header
      buf !~ "\s+Yes\s+(\(ATM labels\))?(\n|$)"          # Does buf have a line that ends in Yes or Yes (ATM labels)
    ) audit(AUDIT_HOST_NOT, "affected because no MPLS interfaces are operational.");

    # Check if we have a Typhoon card, audit out if we dont
    buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
    if (check_cisco_result(buf))
    {
      if (buf =~ "\sA9K-(MOD80|MOD160|24X10GE|36X10GE|2X100GE|1X100GE)-(SE|TR)\s") flag = TRUE;
      else audit(AUDIT_HOST_NOT, "affected because it does not contain a Typhoon-based card.");
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCuo91149' +
    '\n  Installed release : ' + version + 
    '\n';
  security_warning(port:port, extra:report+cisco_caveat(override));
}
else security_warning(port:port, extra:cisco_caveat(override));
