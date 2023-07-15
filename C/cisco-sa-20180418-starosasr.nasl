#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109401);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2018-0273");
  script_bugtraq_id(103935);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve29605");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-starosasr");
  script_xref(name:"IAVA", value:"2018-A-0137-S");

  script_name(english:"Cisco ASR StarOS IPsec Manager Denial of Service Vulnerability (cisco-sa-20180418-starosasr)");
  script_summary(english:"Checks the StarOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and model number, the remote
Cisco ASR device is affected by a denial of service vulnerability.
Please see the included Cisco BID and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-starosasr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb4c762c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve29605");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCve29605.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0273");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:asr_5000_series_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# only affects ASR 5000 series systems
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
  "21.3", make_array("J0", 67141, "M0", 67139, "a0", 68015),
  "21.4", make_array("A0", 67147, "C0", 68000, "D0", 67794,
                     "M0", 67792)
);

if (major == "21.2.6" && int(build) < 67773)
  fix = "21.1.6.67773";
else if (major == "21.4.0" && int(build) < 68051)
  fix = "21.4.0.68051";
else if (!empty_or_null(fix_array[major]) &&
         !empty_or_null(train) &&
         int(build) < fix_array[major][train])
  fix = major + "." + train + "." + fix_array[major][train];

if (fix)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : TRUE,
    version  : version,
    fix      : fix,
    bug_id   : 'CSCve29605'
  );
}
else audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);
