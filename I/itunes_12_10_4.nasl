#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134222);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/06");

  script_cve_id(
    "CVE-2020-3825",
    "CVE-2020-3826",
    "CVE-2020-3846",
    "CVE-2020-3861",
    "CVE-2020-3862",
    "CVE-2020-3864",
    "CVE-2020-3865",
    "CVE-2020-3867",
    "CVE-2020-3868"
  );
  script_xref(name:"APPLE-SA", value:"HT210923");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-1-28-6");

  script_name(english:"Apple iTunes < 12.10.4 Multiple Vulnerabilities (credentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is prior to 12.10.4. It is, therefore, affected by
multiple vulnerabilities as referenced in the HT210923 advisory. Note that Nessus has not tested for this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210923");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.10.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3826");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}
include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'iTunes Version', win_local:TRUE);
constraints = [{'fixed_version':'12.10.4'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
