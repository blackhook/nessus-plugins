#TRUSTED 9e0958036fbb393ef5f5bac4f8635740e07bdf3df8223d2d8feddb34699ea695a7a0939e28b06388742607724cbde8b7026cc01bb705288c61b4f4d2fb430b88e26d0473d79d842eaf8e9b343d4528588dc88fce873852b0f34b7420e1ac699b4bd20b95c6f7642f960947d845ef726cd850d1dd9a0447de43c124a9b0a7b396395e35a7723ca1a4dc3c99b85fc370260c6cce6362724ff3daa565689c1b21cb9792ba25a019b7db3177de8df8380d3132347946827184abff6793e6ad8dcc16f610c98a7bfbcf38dc46cba5aba2c2b7c2216ad5658b595399f277340f4063f3b68bca59c9ef9477e9e24f7212e6189b099600b84c9403cdaaeacfb78804eadb9d1d53e6b7ff7476376dbc8367fc6f18471745a8d7330c7bf2996550c22c50bed1a9dcc6c64b4d29f643faece3dd4566f9ef62ed7d8cb9ce195e9906cec3e5b6afae658e73da6dd8310f81d6f3fde4b7fcd2a33822beaceb8a572833c4d2fdc23aa79ef77898971783ea905bc90ba50986dc611fd5ffbeb5eb815c1f2e25e29fae705192b254d3cb758be26d0a4264aca2dd198ca53061de085bff35ba9d69bbd7451e83929102179a0266d1af2ab725743339a71c476c588b462a6910df403d36bda086888f2a1d656d2b6865170c0d7984b9ff1e2f087647e7dfa8c69cd2a337aafb503f5c7573c6780379fd221b9ecbbd7783c12e2c6342ba25df05cfc6e9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81912);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id(
    "CVE-2014-9293",
    "CVE-2014-9294",
    "CVE-2014-9295",
    "CVE-2014-9296"
  );
  script_bugtraq_id(
    71757,
    71758,
    71761,
    71762
  );
  script_xref(name:"CERT", value:"852879");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus26956");

  script_name(english:"Cisco IOS XR Multiple ntpd Vulnerabilities");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of IOS XR software that
is affected by the following vulnerabilities :

  - Errors exist related to weak cryptographic pseudorandom
    number generation (PRNG), the functions 'ntp_random' and
    and 'config_auth', and the 'ntp-keygen' utility. A
    man-in-the-middle attacker can exploit these to disclose
    sensitive information. (CVE-2014-9293, CVE-2014-9294)

  - Multiple stack-based buffer overflow errors exist in the
    Network Time Protocol daemon (ntpd), which a remote
    attacker can exploit to execute arbitrary code or cause
    a denial of service by using a specially crafted packet.
    (CVE-2014-9295)

  - An error exists in the 'receive' function in the Network
    Time Protocol daemon (ntpd) that allows denial of
    service attacks. (CVE-2014-9296)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141222-ntpd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?292ffa4a");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/534319");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco bug ID
CSCus26956.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9293");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
override = FALSE;

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

# Check model
# per bug page :
# - "NCS6K, NCS4K,ASR9K, CRS, C12K"
model = get_kb_item("CISCO/model");
if (model)
{
  if (
    model !~ "^ciscoASR9[0-9]{3}"
    &&
    model !~ "^cisco([Nn]cs|NCS)(4016|4k|6008|6k)"
    &&
    model !~ "^ciscoCRS\d+(S|SB|B)"
  ) audit(AUDIT_HOST_NOT, "an affected model");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if (
    "ASR9K"   >!< model
    &&
    "NCS6K"   >!< model
    &&
    "NCS6008" >!< model
    &&
    "NCS4016" >!< model
    &&
    "NCS4K"   >!< model
    &&
    "CRS-1"   >!< model
    &&
    "C12K"    >!< model
  ) audit(AUDIT_HOST_NOT, "an affected model");
}

# Check version
# per bug page :
#  - "CSCus26956 impacts all releases prior to XR 5.3.1."
if (
  !(
    version =~ "^[0-4]\."
    ||
    version =~ "^5\.[0-2]\."
    ||
    version =~ "5.3.0($|[^0-9])"
  )
) audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

if (!isnull(get_kb_item("Host/local_checks_enabled")))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status", "show ntp status");
  # Check for traces of ntp
  if (check_cisco_result(buf))
  {
      if (
        "%NTP is not enabled." >< buf
        &&
        "system poll" >!< buf
        &&
        "Clock is" >!< buf
      ) audit(AUDIT_HOST_NOT, "affected because NTP is not enabled.");
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : CSCus26956' +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : 5.3.1.18i.BASE' +
    '\n';
  security_hole(port:port, extra:report+cisco_caveat(override));
}
else security_hole(port:port, extra:cisco_caveat(override));
