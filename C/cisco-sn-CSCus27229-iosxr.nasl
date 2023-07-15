#TRUSTED 798a74c864541e9939d53c53cc66ea08b4c5be06a5713f54d78450874e6af5e4e6de2682345fed7b8a36858266d33516ebccdc23f470d13d3ec5e275a44237700e2e03f232b76fbb301640616c17e52f8fb79e5763dd4ae55d3a1b7d6ec09a7d8032b13bdce446a3d9d0eba5ea29e69b74bffc0f7629ef1954345f0420074ab62df0f9103d270f9f9991a33496592dc3a04a2303820363e04248ab682fcf4839ff3d3a65341e628991905821ef4addcfade37c8ccfc52bbf35c75767aa03cf61d7ae18c880944b6d3acf5124510c84b49ed76d254fb3e74c2ae08832f483c8c0422296028524d87a2dfa91aae31678202806c5a8bf75dbf56af111b7f0709cae835b44f2bc4801891eb6520bd809935e783b4afbc67d0c13c14d6978fdb0bdd176a914799ee2eca7e052d6aa9a5f916a0f93dddc5001bfd7e4b778a19da5461ee2e54a2440ae2ce2bd1e874ca8a41f32a41354a1356b7de334a2ac43a060cf96633cf05d0409942ba3ea9e1ae9c826851956f093fdf57e9aeda13ba2f7e6ae9f5c7ee3e7b8b87ad96fae6f76481761bd54abcbdb7ad0b22f73514754e7ee0cc216af66a51b8d23c97bda911a04117e52b8a9428791ee8fa315782dfc1a13242fe674946200691ff35f7c0116cbd860d587e152380a5c041dec62cb1c9873cf01439b7021b3e5e71cf34a7acf2fdd1fcc6e6a32cb81d26596181e986d8c25d518
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81913);
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
  script_xref(name:"CISCO-BUG-ID", value:"CSCus27229");

  script_name(english:"Cisco IOS XR NCS 6000 Multiple ntpd Vulnerabilities");
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
CSCus27229.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9293");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/03");
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
model = get_kb_item("CISCO/model");
if (model)
{
  if (model !~ "^cisco([Nn]cs|NCS)(6008|6k)")
    audit(AUDIT_HOST_NOT, "an affected model");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if (
    "NCS6K"   >!< model
    &&
    "NCS6008" >!< model
  ) audit(AUDIT_HOST_NOT, "an affected model");
}

# Check version
# per bug page :
#  - "5.2.4.BASE" in "Known Affected" list
if (version != "5.2.4") audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

if (!isnull(get_kb_item("Host/local_checks_enabled")))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_staus", "show ntp status");
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
    '\n  Cisco bug IDs     : CSCus27229' +
    '\n  Installed release : ' + version +
    '\n';
  security_hole(port:port, extra:report+cisco_caveat(override));
}
else security_hole(port:port, extra:cisco_caveat(override));
