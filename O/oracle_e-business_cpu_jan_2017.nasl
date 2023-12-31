#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96608);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-8325",
    "CVE-2017-3246",
    "CVE-2017-3274",
    "CVE-2017-3275",
    "CVE-2017-3277",
    "CVE-2017-3278",
    "CVE-2017-3279",
    "CVE-2017-3280",
    "CVE-2017-3281",
    "CVE-2017-3282",
    "CVE-2017-3283",
    "CVE-2017-3284",
    "CVE-2017-3285",
    "CVE-2017-3286",
    "CVE-2017-3287",
    "CVE-2017-3303",
    "CVE-2017-3326",
    "CVE-2017-3327",
    "CVE-2017-3328",
    "CVE-2017-3333",
    "CVE-2017-3334",
    "CVE-2017-3335",
    "CVE-2017-3336",
    "CVE-2017-3338",
    "CVE-2017-3339",
    "CVE-2017-3340",
    "CVE-2017-3341",
    "CVE-2017-3343",
    "CVE-2017-3344",
    "CVE-2017-3346",
    "CVE-2017-3348",
    "CVE-2017-3349",
    "CVE-2017-3350",
    "CVE-2017-3351",
    "CVE-2017-3352",
    "CVE-2017-3353",
    "CVE-2017-3354",
    "CVE-2017-3357",
    "CVE-2017-3358",
    "CVE-2017-3359",
    "CVE-2017-3360",
    "CVE-2017-3361",
    "CVE-2017-3362",
    "CVE-2017-3363",
    "CVE-2017-3364",
    "CVE-2017-3365",
    "CVE-2017-3366",
    "CVE-2017-3367",
    "CVE-2017-3368",
    "CVE-2017-3369",
    "CVE-2017-3370",
    "CVE-2017-3371",
    "CVE-2017-3372",
    "CVE-2017-3373",
    "CVE-2017-3374",
    "CVE-2017-3375",
    "CVE-2017-3376",
    "CVE-2017-3377",
    "CVE-2017-3378",
    "CVE-2017-3379",
    "CVE-2017-3380",
    "CVE-2017-3381",
    "CVE-2017-3382",
    "CVE-2017-3383",
    "CVE-2017-3384",
    "CVE-2017-3385",
    "CVE-2017-3386",
    "CVE-2017-3387",
    "CVE-2017-3388",
    "CVE-2017-3389",
    "CVE-2017-3390",
    "CVE-2017-3391",
    "CVE-2017-3392",
    "CVE-2017-3394",
    "CVE-2017-3395",
    "CVE-2017-3396",
    "CVE-2017-3397",
    "CVE-2017-3398",
    "CVE-2017-3399",
    "CVE-2017-3400",
    "CVE-2017-3401",
    "CVE-2017-3402",
    "CVE-2017-3403",
    "CVE-2017-3404",
    "CVE-2017-3405",
    "CVE-2017-3406",
    "CVE-2017-3407",
    "CVE-2017-3408",
    "CVE-2017-3409",
    "CVE-2017-3410",
    "CVE-2017-3411",
    "CVE-2017-3412",
    "CVE-2017-3413",
    "CVE-2017-3414",
    "CVE-2017-3415",
    "CVE-2017-3416",
    "CVE-2017-3417",
    "CVE-2017-3418",
    "CVE-2017-3419",
    "CVE-2017-3420",
    "CVE-2017-3421",
    "CVE-2017-3422",
    "CVE-2017-3423",
    "CVE-2017-3424",
    "CVE-2017-3425",
    "CVE-2017-3426",
    "CVE-2017-3427",
    "CVE-2017-3428",
    "CVE-2017-3429",
    "CVE-2017-3430",
    "CVE-2017-3431",
    "CVE-2017-3433",
    "CVE-2017-3435",
    "CVE-2017-3436",
    "CVE-2017-3437",
    "CVE-2017-3438",
    "CVE-2017-3439",
    "CVE-2017-3440",
    "CVE-2017-3441",
    "CVE-2017-3442",
    "CVE-2017-3443"
  );
  script_bugtraq_id(
    95463,
    95464,
    95465,
    95467,
    95468,
    95485,
    95487,
    95490,
    95492,
    95497,
    95500,
    95511,
    95523,
    95526,
    95531,
    95561,
    95564,
    95569,
    95573,
    95577,
    95582,
    95586,
    95587,
    95591,
    95593,
    95594,
    95595,
    95597,
    95598,
    95600,
    95602,
    95604,
    95605,
    95610,
    95611,
    95612,
    95613,
    95614,
    95615,
    95616,
    95617,
    95618
  );

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (January 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the January 2017 Oracle Critical Patch Update (CPU). It is,
therefore, affected by multiple unspecified vulnerabilities in
multiple components and subcomponents, the most severe of which can
allow an unauthenticated, remote attacker to affect both
confidentiality and integrity. The affected components and
subcomponents are as follows :

  - Oracle Advanced Outbound Telephony : User Interface
  - Oracle Application Object Library : Patching
  - Oracle Applications DBA : Patching
  - Oracle Applications Manager : OAM Client
  - Oracle Common Applications : Resources Module
  - Oracle Common Applications : Role Summary
  - Oracle Common Applications : User Interface
  - Oracle CRM Technical Foundation : User Interface
  - Oracle Customer Intelligence : User Interface
  - Oracle Customer Interaction History : User Interface
  - Oracle Email Center : User Interface
  - Oracle Fulfillment Manager : User Interface
  - Oracle Installed Base : User Interface
  - Oracle Interaction Blending : User Interface
  - Oracle iStore : Address Book
  - Oracle iStore : User Interface
  - Oracle Knowledge Management : User Interface
  - Oracle Leads Management : User Interface
  - Oracle Marketing : User Interface
  - Oracle One-to-One Fulfillment : Internal Operations
  - Oracle One-to-One Fulfillment : Request Confirmation
  - Oracle One-to-One Fulfillment : User Interface
  - Oracle Partner Management : User Interface
  - Oracle Service Fulfillment Manager : User Interface
  - Oracle Universal Work Queue : User Interface
  - Oracle XML Gateway : Oracle Transport Agent");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html#AppendixEBS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f2c97c2");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2017 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3346");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Oracle/E-Business/Version");
patches = get_kb_item_or_exit("Oracle/E-Business/patches/installed");

# Batch checks
if (patches) patches = split(patches, sep:',', keep:FALSE);
else patches = make_list();

p12_1 = '25032333';
p12_2 = '25032335';

# Check if the installed version is an affected version
affected_versions = make_array(
  '12.1.1', make_list(p12_1),
  '12.1.2', make_list(p12_1),
  '12.1.3', make_list(p12_1),

  '12.2.3', make_list(p12_2),
  '12.2.4', make_list(p12_2),
  '12.2.5', make_list(p12_2),
  '12.2.6', make_list(p12_2)
);

patched = FALSE;
affectedver = FALSE;

if (affected_versions[version])
{
  affectedver = TRUE;
  patchids = affected_versions[version];
  foreach required_patch (patchids)
  {
    foreach applied_patch (patches)
    {
      if(required_patch == applied_patch)
      {
        patched = applied_patch;
        break;
      }
    }
    if(patched) break;
  }
  if(!patched) patchreport = join(patchids,sep:" or ");
}

if (!patched && affectedver)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+version+' Patch '+patchreport+
      '\n';
    security_warning(port:0,extra:report);
  }
  else security_warning(0);
  exit(0);
}
else if (!affectedver) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle E-Business', version);
else exit(0, 'The Oracle E-Business server ' + version + ' is not affected because patch ' + patched + ' has been applied.');
