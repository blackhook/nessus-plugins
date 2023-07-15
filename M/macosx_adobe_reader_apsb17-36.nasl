#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104672);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/18");

  script_cve_id(
    "CVE-2017-11240",
    "CVE-2017-11250",
    "CVE-2017-11293",
    "CVE-2017-11306",
    "CVE-2017-11307",
    "CVE-2017-11308",
    "CVE-2017-16360",
    "CVE-2017-16361",
    "CVE-2017-16362",
    "CVE-2017-16363",
    "CVE-2017-16364",
    "CVE-2017-16365",
    "CVE-2017-16366",
    "CVE-2017-16367",
    "CVE-2017-16368",
    "CVE-2017-16369",
    "CVE-2017-16370",
    "CVE-2017-16371",
    "CVE-2017-16372",
    "CVE-2017-16373",
    "CVE-2017-16374",
    "CVE-2017-16375",
    "CVE-2017-16376",
    "CVE-2017-16377",
    "CVE-2017-16378",
    "CVE-2017-16379",
    "CVE-2017-16380",
    "CVE-2017-16381",
    "CVE-2017-16382",
    "CVE-2017-16383",
    "CVE-2017-16384",
    "CVE-2017-16385",
    "CVE-2017-16386",
    "CVE-2017-16387",
    "CVE-2017-16388",
    "CVE-2017-16389",
    "CVE-2017-16390",
    "CVE-2017-16391",
    "CVE-2017-16392",
    "CVE-2017-16393",
    "CVE-2017-16394",
    "CVE-2017-16395",
    "CVE-2017-16396",
    "CVE-2017-16397",
    "CVE-2017-16398",
    "CVE-2017-16399",
    "CVE-2017-16400",
    "CVE-2017-16401",
    "CVE-2017-16402",
    "CVE-2017-16403",
    "CVE-2017-16404",
    "CVE-2017-16405",
    "CVE-2017-16406",
    "CVE-2017-16407",
    "CVE-2017-16408",
    "CVE-2017-16409",
    "CVE-2017-16410",
    "CVE-2017-16411",
    "CVE-2017-16412",
    "CVE-2017-16413",
    "CVE-2017-16414",
    "CVE-2017-16415",
    "CVE-2017-16416",
    "CVE-2017-16417",
    "CVE-2017-16418",
    "CVE-2017-16419",
    "CVE-2017-16420"
  );
  script_bugtraq_id(
    101812,
    101813,
    101814,
    101815,
    101816,
    101817,
    101818,
    101819,
    101820,
    101821,
    101823,
    101824,
    101830,
    101831
  );

  script_name(english:"Adobe Reader < 11.0.23 / 2015.006.30392 / 2017.011.30068 / 2018.009.20044 Multiple Vulnerabilities (APSB17-36) (macOS)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS or Mac OS X
host is a version prior to 11.0.23, 2015.006.30392, 2017.011.30068,
or 2018.009.20044. It is, therefore, affected by multiple
vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb17-36.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 11.0.23 / 2015.006.30392 / 2017.011.30068
/ 2018.009.20044 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11293");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item("Host/MacOSX/Version");
if (empty_or_null(os)) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"Adobe Reader");
base_dir = app_info['path'] - "/Applications";
track = get_kb_item("MacOSX/Adobe_Reader"+base_dir+"/Track");

if (!isnull(track) && track == '2017')
{
  constraints = [
    { "min_version" : "17.8", "fixed_version" : "17.11.30068"  }
  ];

}
else
{
  constraints = [
    { "min_version" : "11", "fixed_version" : "11.0.23"  },
    { "min_version" : "15.6", "fixed_version" : "15.6.30392"  },
    { "min_version" : "15.7", "fixed_version" : "18.9.20044"  }
  ];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
