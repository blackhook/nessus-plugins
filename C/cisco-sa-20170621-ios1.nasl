#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101267);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2017-6718");
  script_bugtraq_id(99226);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb99384");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170621-ios1");

  script_name(english:"Cisco IOS XR Software Privilege Escalation (cisco-sa-20170621-ios1)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XR software
running on the remote device is affected by a privilege escalation
vulnerability in the command line interface due to incorrect
permission settings on binary files. A local attacker can exploit
this, via specially crafted commands, to overwrite binary files on the
filesystem and thereby gain elevated root privileges.

Note that this vulnerability only affects Linux-based versions of
Cisco IOS XR software.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170621-ios1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8050ccd6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb99384");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvb99384.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6718");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;

# Known Affected releases: 6.2.1.BASE, 6.0.2, 6.0.2.1
if (version == "6.2.1" || version == "6.0.2" || version == "6.0.2.1")
{
  security_report_cisco(
    port     : port,
    severity : SECURITY_HOLE,
    version  : version,
    bug_id   : "CSCvb99384"
  );
}
else audit(AUDIT_HOST_NOT, "affected");

