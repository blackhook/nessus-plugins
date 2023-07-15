#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107095);
  script_version("1.6");
  script_cvs_date("Date: 2018/07/06 11:26:06");

  script_cve_id("CVE-2018-0115", "CVE-2018-0217", "CVE-2018-0224");
  script_bugtraq_id(102788, 103344, 103346);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf93332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg29441");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg38807");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180117-staros");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180307-staros");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180307-staros1");

  script_name(english:"Cisco ASR StarOS Multiple CLI Command Injection Vulnerabilities (cisco-sa-20180117-staros / cisco-sa-20180307-staros / cisco-sa-20180307-staros1)");
  script_summary(english:"Checks the StarOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple command injection
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and model number, the remote
Cisco ASR device is affected by multiple command injection
vulnerabilities due to improper validation of user input. An
authenticated local attacker, using command arguments, could
potentially execute arbitrary commands with root privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180117-staros
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5aae5b06");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180307-staros
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2d6f9a1");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180307-staros1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c6ab9fa");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf93332");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg29441");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg38807");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvf93332, CSCvg29441, or CSCvg38807.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:asr_5000_series_software");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASR/Model", "Host/Cisco/StarOS", "Settings/ParanoidReport");
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
if (model !~ "^50\d{2}$")
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
  audit(AUDIT_VER_FORMAT, version);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

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
  "21.4", make_array("C0", 68040, "D0", 68036, "M0", 68033),
  "21.5", make_array("C0", 68318, "M0", 68317),
  "21.6", make_array("A0", 68321, "D0", 68319, "RU0", 68455),
  "21.7", make_array("D0", 68717, "M0", 68711)
);

if (major == "21.3.5" && int(build) < 68140)
  fix = "21.3.5.68140";
else if (major == "21.4.0" && int(build) < 68051)
  fix = "21.4.0.68051";
else if (major == "21.5.0" && int(build) < 68363)
  fix = "21.5.0.68363";
else if (major == "21.7.0" && int(build) < 68846)
  fix = "21.7.0.68846";
else if (!empty_or_null(fix_array[major]) &&
         !empty_or_null(train) &&
         int(build) < fix_array[major][train])
  fix = major + "." + train + "." + fix_array[major][train];

if (fix)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : TRUE,
    version  : version,
    fix      : fix,
    bug_id   : 'CSCvf93332, CSCvg29441, or CSCvg38807'
  );
}
else audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);
