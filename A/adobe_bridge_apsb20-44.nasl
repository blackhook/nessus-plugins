##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147418);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2020-9674", "CVE-2020-9675", "CVE-2020-9676");

  script_name(english:"Adobe Bridge 10.x < 10.1.1 Multiple Vulnerabilities (APSB20-44)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote Windows host is prior to 10.1.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the apsb20-44 advisory.

  - Adobe Bridge versions 10.0.3 and earlier have an out-of-bounds write vulnerability. Successful
    exploitation could lead to arbitrary code execution. (CVE-2020-9674, CVE-2020-9676)

  - Adobe Bridge versions 10.0.3 and earlier have an out-of-bounds read vulnerability. Successful exploitation
    could lead to arbitrary code execution. (CVE-2020-9675)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb20-44.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 10.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9676");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_bridge_installed.nasl");
  script_require_keys("installed_sw/Adobe Bridge", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Bridge', win_local:TRUE);

constraints = [
  { 'min_version' : '10.0.0', 'max_version' : '10.0.3', 'fixed_version' : '10.1.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
