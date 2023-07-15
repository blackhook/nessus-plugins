#TRUSTED ab1e9b007d97ecfaaa384e555a41f45cf4d22a09acd9ac536206f7621177d124093db9f972a2e90c9a101e6b301d995015e7eb347486ba11abd5dc9adb32b43511d3328b62ac475092c924270b45cd3babace00accf1ff05a165e7b46a5a0a81899d0f2c8261b4bf3666a02f35ec623d346dc258f622fd72f3545d9a6c669c28e55b5ce1969fa46ab883b12f20005a295008140e0a6966b5bea95e805fd62094efa885ff6434d0b4db72cb0c3e305c67a1182d9401a8fe7380d5bdd8a444b73e4dd4149f5e1756f4d211eb30a5455ed9337aaee5d74556f57bdbeb0bb3dda48467c81f39a24cbd9a39e03e33d7808fbdc1ef9041cb22dffc540a3ce33d025b4e0646df5b03a49b9e8c64394a57540251a813913d198ab4cdf06684b816e744123bb76e3317e469c0165351f50a4b1ad025deab042d4059b6a0b4c264e3790713db2225750556819114d7860fd61ad5a026052ec9115a5fa2232d9f625927da3a2a23fd05fe6afe6b87e6d8178cf9c2872eb5f39d5d4a7eff43e1a586c4a932b04357d6f8121d1ffde05d5cb530c4cc27fcc8c95fcd13a64e782bd9da927eebaf55d27629762de51b36933a8fbdf6fe01dfa727f35ea9a2326f85c8a3d104b9bc08f4425d5925d6c5dfe8526936911fc7ed0a794ad8bdfd2782c0f95f4f013704951583a60a10398546aed93e120207e8e5094a738c46dd86f31c6db2829a334c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102202);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-3865");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc21129");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170621-asr");

  script_name(english:"Cisco StarOS for ASR 5000 Series Routers IPsec VPN Tunnel DoS (cisco-sa-20170621-asr)");
  script_summary(english:"Checks the StarOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and model number, the remote
Cisco ASR device is affected by a denial of service vulnerability in
StarOS in the IPsec component that is triggered during the handling
of specially crafted IKE messages. This may allow a remote attacker
to terminate all active IPsec VPN tunnels and prevent new tunnels
from establishing.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170621-asr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4fe9746");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvc21129");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvc21129.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:asr_5000_series_software");
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
flag = NULL;

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
  "21.1", make_array( "M0", 65749, "R0", 65759,
                      "V0", 66014, "B0", 66164 ),
  "21.2", make_array( "A0", 65754 )
);

if (major == "21.1.0" && int(build) < 66030)
  fix = "21.1.0.66030";

else if (
          !empty_or_null(fix_array[major]) &&
          !empty_or_null(train) &&
          int(build) < fix_array[major][train]
        )
  fix = strcat(major, ".", train, ".", fix_array[major][train]);

if (!isnull(fix))
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    version  : version,
    fix      : fix,
    bug_id   : 'CSCvc21129'
  );
}
else audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);
