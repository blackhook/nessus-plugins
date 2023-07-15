#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(89869);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2016-0960",
    "CVE-2016-0961",
    "CVE-2016-0962",
    "CVE-2016-0963",
    "CVE-2016-0986",
    "CVE-2016-0987",
    "CVE-2016-0988",
    "CVE-2016-0989",
    "CVE-2016-0990",
    "CVE-2016-0991",
    "CVE-2016-0992",
    "CVE-2016-0993",
    "CVE-2016-0994",
    "CVE-2016-0995",
    "CVE-2016-0996",
    "CVE-2016-0997",
    "CVE-2016-0998",
    "CVE-2016-0999",
    "CVE-2016-1000",
    "CVE-2016-1001",
    "CVE-2016-1002",
    "CVE-2016-1005",
    "CVE-2016-1010"
  );
  script_bugtraq_id(
    84308,
    84310,
    84311,
    84312
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Adobe AIR for Mac <= 20.0.0.260 Multiple Vulnerabilities (APSB16-08)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe AIR installed on the remote Mac OS X host is
prior or equal to version 20.0.0.260. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple integer overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2016-0963,
    CVE-2016-0993, CVE-2016-1010)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2016-0987,
    CVE-2016-0988, CVE-2016-0990, CVE-2016-0991,
    CVE-2016-0994, CVE-2016-0995, CVE-2016-0996,
    CVE-2016-0997, CVE-2016-0998, CVE-2016-0999,
    CVE-2016-1000)

  - A heap overflow condition exists that allows an attacker
    to execute arbitrary code. (CVE-2016-1001)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2016-0960,
    CVE-2016-0961, CVE-2016-0962, CVE-2016-0986,
    CVE-2016-0989, CVE-2016-0992, CVE-2016-1002,
    CVE-2016-1005)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-08.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR version 21.0.0.176 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1010");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_air_installed.nasl");
  script_require_keys("MacOSX/Adobe_AIR/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/Adobe_AIR";
version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path");

# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = '20.0.0.260';
fixed_version_for_report = '21.0.0.176';

if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version_for_report +
      '\n';
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version, path);
