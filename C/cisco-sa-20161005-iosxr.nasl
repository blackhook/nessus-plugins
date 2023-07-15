#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94354);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2016-6428");
  script_bugtraq_id(93416);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva38349");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161005-iosxr");

  script_name(english:"Cisco IOS XR Software Command-Line Interface Privilege Escalation (cisco-sa-20161005-iosxr)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XR software
running on the remote device is affected by a local privilege
escalation vulnerability in the command-line interface (CLI) due to
incorrect permissions being given to a certain set of users. A local
attacker who has valid administrative credentials can exploit this
issue, by sending specially crafted input, to execute commands on the
underlying operating system.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f23f9621");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva38349.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6428");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

# Known Affected releases: 6.1.1.BASE
if (version == "6.1.1")
{
  security_report_cisco(
    port     : port,
    severity : SECURITY_HOLE,
    version  : version,
    bug_id   : "CSCva38349"
  );
}
else audit(AUDIT_HOST_NOT, "affected");
