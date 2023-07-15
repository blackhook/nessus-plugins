#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108795);
  script_version("1.6");
  script_cvs_date("Date: 2019/04/05 23:25:09");

  script_cve_id(
    "CVE-2018-4101",
    "CVE-2018-4113",
    "CVE-2018-4114",
    "CVE-2018-4117",
    "CVE-2018-4118",
    "CVE-2018-4119",
    "CVE-2018-4120",
    "CVE-2018-4121",
    "CVE-2018-4122",
    "CVE-2018-4125",
    "CVE-2018-4127",
    "CVE-2018-4128",
    "CVE-2018-4129",
    "CVE-2018-4130",
    "CVE-2018-4144",
    "CVE-2018-4146",
    "CVE-2018-4161",
    "CVE-2018-4163",
    "CVE-2018-4165"
);
  script_bugtraq_id(102775);

  script_name(english:"Apple iTunes < 12.7.4 WebKit Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.7.4. It is, therefore, affected by multiple vulnerabilities
in WebKit as referenced in the HT208694 advisory.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208694");
  script_set_attribute(attribute:"solution", value:
  "Upgrade to Apple iTunes version 12.7.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4144");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

# Ensure this is Windows
get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"iTunes Version", win_local:TRUE);

constraints = [{"fixed_version" : "12.7.4"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
