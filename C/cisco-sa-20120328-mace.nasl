#TRUSTED 1b11c742ae7827214d3ac94057c2e987f4093eba3a8354a4e93364b6501624de4790eba6b74672691c0c44305132d6886bcb806e568be4a3aff7f176d3f060a8608a73af2d5e9ca8f12d535acab429d7496af2489470578e00a9d39367a0502ed4817545dff244399a4fa64c89d783bd1cb2e66b6bef52c8a32afca3ba6762952a5f20c752b1f594bdfe3c31730c5602113a39a4a9c017d5a144fe3c04bfd5d61cf0c408e6d69eb38d1d2aa32e4351feaaa02380552c3d90adb13080b68c60ae3e1c8c37046aeb317486d2ea6c9ee34a451b71255698edf08fb4b45f971f738609161e896438e59ebb01637c2fcf14991a18644dcbe7cf0c75781086cc6844341cf83a5923ce6e031aa89b732d0f86da0031b7f9aeb8ded9e8e5efb1b8a0d9ed4b03be9faecba11e24b05e8cf597a90acda5a535345ab5bf447c9ec6d7e6c7f688a6eecc054e7efbbf35e6b3f3d322d4c46816e3541e6ee3f5027784d33e42076a6898b034bf2df6f70de41a3e5e949bb3961ee2af04601fd856c872e5114ede4bda32b71b12eaa294eeea5ff8c5200071ab014c43c0956497b2a14b2a8e2fb791694d0dbb0148f593328584cc4383ad0246e741de4cc857b7bd995e1a56e4d0cf84a3f818dcc9067ac2eab145484c2edc45e20a511b0f461ebe1e7784b69a3a84ba03d7a95adb1e33b11122f3d79b5fd3d82a8abbcc0415152f354924418b6e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58567);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2012-1312", "CVE-2012-1314");
  script_bugtraq_id(52751);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq64987");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt45381");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtu57226");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120328-mace");

  script_name(english:"Cisco IOS Software Traffic Optimization Features Multiple DoS");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS installed on the remote device is affected
by multiple denial of service vulnerabilities due to message parsing
flaws related to the Wide Area Application Services (WAAS) Express
feature and the Measurement, Aggregation, and Correlation Engine
(MACE) feature. A remote, unauthenticated attacker can exploit these
flaws, via crafted requests, to cause a device reload or consumption
of memory, resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120328-mace
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec691d50");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120328-mace.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

vuln     = FALSE;
override = FALSE;
  
vuln_versions = make_list(
  "15.2(2)T",
  "15.2(1)T1",
  "15.2(1)T",
  "15.2(1)GC1",
  "15.2(1)GC",
  "15.1(4)M3a",
  "15.1(4)M3",
  "15.1(4)M2",
  "15.1(4)M1",
  "15.1(4)M0b",
  "15.1(4)M0a",
  "15.1(4)M"
);

foreach ver (vuln_versions)
{
  if (ver == version)
  {
    vuln = TRUE;
    break;
  }
}

if (!vuln) audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS', version);

bugs = make_list();

# Check for WAAS Express or MACE
if (vuln && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config",
                              "show running-config");
  if (check_cisco_result(buf))
  {
    # WAAS Express : 2 checks for WAAS Express to distinguish it from WAAS
    if (preg(multiline:TRUE, pattern:"^(parameter|policy)-map type waas ", string:buf) &&
        preg(multiline:TRUE, pattern:"^\s*waas enable", string:buf))
      bugs = make_list("CSCtt45381");
    # MACE check
    if (preg(multiline:TRUE, pattern:"^\s*mace enable", string:buf))
      bugs = make_list(bugs, "CSCtq64987", "CSCtu57226");
  }
  else if (cisco_needs_enable(buf))
  {
    bugs     = make_list("CSCtt45381", "CSCtq64987", "CSCtu57226");
    override = TRUE;
  }
}

if (empty(bugs)) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : ' + join(bugs, sep:' / ') +
    '\n  Installed release : ' + ver +
    '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
