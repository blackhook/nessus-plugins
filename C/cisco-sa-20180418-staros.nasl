#TRUSTED 94d8f13969e31015918dd2049263ee8534e6b292b35e70e0217e0a9e3cb493988d257778e40f29d8157a56a3c1bc25701c3bda192621cdefccf6d3f7992256196285e9bd341903b7c3d778154f60fda7d7bd36117fa79997112cf330b90f647fcb2e26c78ced378c55e4260304b2765c83e579e2d3b0f93167ce4a7d8f7bc4fa6f295c1e9ea197db60235e3c4dfd2a2e183273d4b299bb69db1fb3e802da99a1060d3a4169e7b9dcd7c3ed3d8b99795d6dbb37eb6321d8972cb85291bf55c9c77121338735a709913f188db9fb87933a8eb2b78c602d94c0d7e75403b43e1ba6f09a019ffe1f6392b8e28945b84d7a1c54508e846bc480419fccb37af46458d227dc054448bffd5e3628de8363fe38f4e7e8c2917e9edc48b9240a0f999242346aa6d66b261dbfdb168e2abcb3ae96dacbb291ab9b2a80b2dcac337d02205fbf48e066599b8c460083091be0c471065bc4a8cbd359c351a937e4db67db7186402cb2d7a40a01cb9f3a1cd0fe14967addd1b50cabaeb7e4ff5de07e5e26e7d872005bfa28379af87ccaa97aed451573172416be8a361e648b1a95a3278b6ab3cc2c4de012e582ad406fb8b168d3e04ed16128bf37cd2afbe38d51ecaa2c06212432bc3fa95ac1b925d9c88c34673c01697a3b51a18354fd9ed13f86102e2c74edaaf94b40b73474b0291eb56cd76c1b2c7f197841eb80a4345448f921374bd81f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109400);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2018-0239");
  script_bugtraq_id(103923);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf32385");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-staros");
  script_xref(name:"IAVA", value:"2018-A-0137-S");

  script_name(english:"Cisco ASR StarOS Interface Forwarding Denial of Service Vulnerability (cisco-sa-20180418-staros)");
  script_summary(english:"Checks the StarOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and model number, the remote
Cisco ASR device is affected by a denial of service vulnerability.
Please see the included Cisco BID and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-staros
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b84fc064");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf32385");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvf32385.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0239");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5700");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:asr_5700_series_software");
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

# only affects ASR 5700 series systems
if (model !~ "^57\d{2}$")
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
  "21.0", make_array("v4", 67670),
  "21.1", make_array("v6", 67740),
  "21.4", make_array("C0", 68000, "D0", 67675, "M0", 67671)
);

if (major == "21.3.1" && int(build) < 67739)
  fix = "21.3.1.67739";
else if (major == "21.4.0" && int(build) < 68051)
  fix = "21.4.0.68051";
else if (!empty_or_null(fix_array[major]) &&
         !empty_or_null(train) &&
         int(build) < fix_array[major][train])
  fix = major + "." + train + "." + fix_array[major][train];
else audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);

override = FALSE;
flag = FALSE;

if (get_kb_item("Host/local_checks_enabled"));
{
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_support_details_grep_Cisco_VIC",
    "show support details | grep 'Cisco VIC'"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"Cisco VIC", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because vulnerable features are not enabled");
}

security_report_cisco(
  port     : 0,
  severity : SECURITY_WARNING,
  override : override,
  version  : version,
  fix      : fix,
  bug_id   : 'CSCvf32385'
);
