#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107091);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0123");
  script_bugtraq_id(102967);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg41950");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180207-ios");
  script_xref(name:"IAVA", value:"2018-A-0068-S");

  script_name(english:"Cisco IOS XE Software Diagnostic Shell Path Traversal Vulnerability (cisco-sa-20180207-ios)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a path traversal
vulnerability. A flaw exists with the diagnostic shell due to improper
validation of diagnostic shell commands. An authenticated attacker,
with a specially craft command, could potentially overwrite restricted
system files.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180207-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73faf25a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg41950");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20180207-ios.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0123");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
port = get_kb_item("Host/Cisco/IOS-XE/Port");
if (empty_or_null(port))
  port = 0;

# 16.7(1) is actually 16.7.1
if (ver == "16.7.1")
{
  security_report_cisco(
    port     : port,
    severity : SECURITY_WARNING,
    version  : ver,
    bug_id   : "CSCvg41950"
  );
}
else audit(AUDIT_HOST_NOT, "affected");
