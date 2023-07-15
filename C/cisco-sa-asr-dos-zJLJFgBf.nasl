#TRUSTED 4fb49272c0cb580640d3102b8ad4cc73ffdf97092d1c4b24ee89b764b9206fb18b11c3ed0dab0699fb608eb74ae8f3aba9b997e82a3b3617223d5097755e83766702fb1faaa8d7dd1783b0975adfaca646d48c048f6c2178db71cf09b89fe136d99ddc8f14cdd4d6c50677491e11f6a3d3047a0f5d1377f03226ad914b30176199d4cd1ef57cdeef29fca53dbb930a806250a5760da749b8c61def92de8612fc416fe6c4f25cd191912fd27b0cd85ac7fc7e019ffc1b1ef58ab19adf1cc49251e9ed705f35223e234ab41052657eae78d0be0d18f41181c6af46706c9d2dc3f4b192861a205ab80a25487dd62bc24fbc60bd6291b0edecd327e6f818a50fab50b85b9bca553cc82c5dc081b2e01375a74a643b3b190bfca3ec1b60f8d4396ad3aaba2d888ecf4af77bc4a19e50cf0e96ad9c2303bca21ceab894f332070e5b1a092a3dddea9f553d176f6ba412dbe8b84063e72c9515b00bb4f5aba286ba0803ea8abea15b0af288fc7194e647b85b5c537d59ba82782faf2157506127c52f9425f6da35924e6f649f778ac2422163f373aa04b2aa0b3f205d6d78d7c3761ab8a093f0af4325bb99530bc26a794de142b39945c9e23de92fb57a96e41cc749e2881a6a9f512ea4bdda210f16ddac6b17db123a40911941d14d890de3a1690f29d0b5c9fd1587a156915cb185b7e9411cc486e63cb9b4122b433e75bf7b484d3d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139425);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2020-3324");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50343");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asr-dos-zJLJFgBf");
  script_xref(name:"IAVA", value:"2020-A-0352-S");

  script_name(english:"Cisco StarOS IPv6 Denial of Service Vulnerability (cisco-sa-asr-dos-zJLJFgBf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASR 5000 Series Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asr-dos-zJLJFgBf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50fa355f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50343");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs50343");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3324");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asr_5000_series");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASR/Model", "Host/Cisco/StarOS", "Settings/ParanoidReport");

  exit(0);
} 

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# only Vector Packet Processing feature affected
if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("Host/Cisco/StarOS");

version  = get_kb_item_or_exit("Host/Cisco/StarOS/Version");
model   = get_kb_item_or_exit("Host/Cisco/ASR/Model");

major = NULL;
build = NULL;
fix   = NULL;
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

# extract major, train, and build for new style
extract = pregmatch(pattern:"^([\d\.]+)\.([A-Z]{1,2}\d+)?\.?(\d+)?", string:version);
if (!isnull(extract))
{
  major = extract[1];
  train = extract[2];
  if (isnull(build))
    build = extract[3];
  display(' extracting info [' + major + '][' + train +'][' + build + ']'); 
}

# Defensive checking for versions that we haven't yet seen
if(empty_or_null(major) || empty_or_null(build))
  exit(1, "An error occurred during version extraction.");

fix_array = make_array(
  "21.21", { CN0: 76816 },
  "21.20",  { VP0: 75670, M0:75446, G0:75425, A0:74472 },
  "21.19", { N1: 0 }, 
  "21.18", { VP0: 74552, M0: 74531, G0: 74463 },
  "21.16", { D2: 75267, C11: 75260 },
  "21.15", { A0: 75998 }
);

maj_checks = [
  {maj:'21.19.0',  build:75454},
  {maj:'21.18.0',  build:74538},
  {maj:'21.17.4',  build:74405},
  {maj:'21.16.4',  build:75269},
  {maj:'21.15.31', build:75264}
];

foreach check (maj_checks)
{
  if (major == check.maj && int(build) < check.build)
  {
    fix = check.maj + '.' + check.build;
    break;
  }
}

if (empty_or_null(fix) &&
    !empty_or_null(fix_array[major]) &&
         !empty_or_null(train) &&
         int(build) < fix_array[major][train])
  fix = major + "." + train + "." + fix_array[major][train];

if (fix)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    version  : version,
    fix      : fix,
    bug_id   : 'CSCvs50343'
  );
}
else audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);
