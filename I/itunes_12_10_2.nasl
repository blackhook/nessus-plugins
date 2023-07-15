#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131132);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id(
    "CVE-2019-8782",
    "CVE-2019-8783",
    "CVE-2019-8784",
    "CVE-2019-8801",
    "CVE-2019-8808",
    "CVE-2019-8811",
    "CVE-2019-8812",
    "CVE-2019-8813",
    "CVE-2019-8814",
    "CVE-2019-8815",
    "CVE-2019-8816",
    "CVE-2019-8819",
    "CVE-2019-8820",
    "CVE-2019-8821",
    "CVE-2019-8822",
    "CVE-2019-8823"
  );
  script_xref(name:"APPLE-SA", value:"HT210726");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-10-25");

  script_name(english:"Apple iTunes < 12.10.2 Multiple Vulnerabilities (credentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is prior to 12.10.2. It is, therefore, affected by
multiple vulnerabilities as referenced in the HT210726 advisory. Note that Nessus has not tested for this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210726");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.10.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8784");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}
include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"iTunes Version", win_local:TRUE);
constraints = [{'fixed_version':'12.10.2'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);