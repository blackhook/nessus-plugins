#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153850);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/26");

  script_cve_id("CVE-2021-30835", "CVE-2021-30847", "CVE-2021-30849");
  script_xref(name:"APPLE-SA", value:"HT212817");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-09-20");

  script_name(english:"Apple iTunes < 12.12 Multiple Vulnerabilities (credentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is prior to 12.12. It is, therefore, affected by
multiple vulnerabilities as referenced in the HT212817 advisory.

  - Processing a maliciously crafted image may lead to arbitrary code execution (CVE-2021-30835,
    CVE-2021-30847)

  - Processing maliciously crafted web content may lead to arbitrary code execution (CVE-2021-30849)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212817");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30849");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}
include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'iTunes Version', win_local:TRUE);
var constraints = [{'fixed_version':'12.12'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
