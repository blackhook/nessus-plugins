#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101528);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-6707");
  script_bugtraq_id(99462);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc69329");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc72930");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170705-asrcmd");
  script_xref(name:"IAVA", value:"2017-A-0205");

  script_name(english:"Cisco ASR StarOS CLI Command Injection Local Privilege Escalation (cisco-sa-20170705-asrcmd)");
  script_summary(english:"Checks the StarOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and model number, the remote
Cisco ASR device is affected by a privilege escalation vulnerability
in StarOS in the Command Line Interface (CLI) due to improper
sanitization of commands passed to the Linux shell. A local attacker
can exploit this, via specially crafted CLI commands, to execute
arbitrary shell commands with root privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170705-asrcmd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e199024c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc69329");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc72930");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvc69329 or CSCvc72930.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6707");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5700");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:asr_5000_series_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:asr_5500_series_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:asr_5700_series_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASR/Model", "Host/Cisco/StarOS");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

get_kb_item_or_exit("Host/Cisco/StarOS");

version  = get_kb_item_or_exit("Host/Cisco/StarOS/Version");
model   = get_kb_item_or_exit("Host/Cisco/ASR/Model");

major = NULL;
build = NULL;
fix = NULL;
train = NULL;

# only affects ASR 5000/5500/5700 series systems
if (model !~ "^5[057]\d{2}$")
  audit(AUDIT_DEVICE_NOT_VULN, 'The ASR ' + model);

# Normalize train characters
version= toupper(version);

# For newer versions, We may be able to get the build number during detection
build = get_kb_item("Host/Cisco/StarOS/Build");
if (!empty_or_null(build))
  version += "." + build;

# defensive check for the pregmatches below
if (version !~ "^[\d\.]+\([\d\.]+" &&
    version !~ "^[\d\.]+([A-Z]{1,2}\d+)?\.\d+$")
  audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);

# old style of versioning 15.0(5439), style change mid 16.1, making
# all of the old style versions fall into the vulnerable range.
if ("(" >< version)
{
  major = pregmatch(pattern:"^([\d\.]+)\(", string:version);

  if(!isnull(major))
  {
    major = major[1];

    if (isnull(build))
    {
      build = pregmatch(pattern:"^[\d\.]+\(([\d\.]+)", string:version);
      if(!isnull(build))
      {
        build = build[1];

        # Set the train to an empty string, or it causes issues when
        # seeing if a patched version exists using NULL as the value
        train = '';
      }
      else
        exit(1, "Unable to extract build number.");
    }
  }
  else
    exit(1, "Unable to extract version number.");
}
else
{
  # extract major, train, and build for new style
  extract = pregmatch(pattern:"^([\d\.]+)\.([A-Z]{1,2}\d+)?\.?(\d+)?", string:version);
  if (!isnull(extract))
  {
    major = extract[1];
    train = extract[2];
    if (isnull(build))
      build = extract[3];
  }
}

# Defensive checking for versions that we haven't yet seen
if(empty_or_null(major) || empty_or_null(build))
  exit(1, "An error occurred during version extraction.");

fix_array = make_array(
  "19.7", make_array( "M0", 67024 ),
  "20.3", make_array( "M0", 66152, "T0", 66156 ),
  "20.4", make_array( "M0", 67029, "T0", 67030 ),
  "21.1", make_array( "V0", 66492, "b0", 66191 )
);

# CVRF states that 11.0 is the first vulnerable
if (ver_compare(ver:major, minver:"11.0", fix:"18.7.6", strict:FALSE) < 0)
  fix = "18.7.6.67108";
else if (ver_compare(ver:major, minver:"19.0", fix:"19.6.5", strict:FALSE) < 0)
  fix = "19.6.5.67022";
else if (ver_compare(ver:major, minver:"20.0", fix:"20.2.8", strict:FALSE) < 0)
  fix = "20.2.8.66150";
else if (ver_compare(ver:major, minver:"21.0", fix:"21.1.0", strict:FALSE) < 0)
  fix = "21.1.0.66134";

if (major == "18.7.6" && int(build) < 67108)
  fix = "18.7.6.67108";
else if (major == "19.6.5" && int(build) < 67022)
  fix = "19.6.5.67022";
else if (major == "20.2.1" && int(build) < 66167)
  fix = "20.2.8.66167";
else if (major == "21.1.0" && int(build) < 66177)
  fix = "21.1.0.66177";

else if (
          !empty_or_null(fix_array[major]) &&
          !empty_or_null(train) &&
          int(build) < fix_array[major][train]
        )
  fix = major + "." + train + "." + string(fix_array[major][train]);

if (!isnull(fix))
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    version  : version,
    fix      : fix,
    bug_id   : 'CSCvc69329 and CSCvc72930'
  );
}
else audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);
