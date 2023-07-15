#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154719);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/23");

  script_cve_id(
    "CVE-2021-40792",
    "CVE-2021-40793",
    "CVE-2021-40794",
    "CVE-2021-40796",
    "CVE-2021-42263",
    "CVE-2021-42264"
  );
  script_xref(name:"IAVA", value:"2021-A-0515-S");

  script_name(english:"Adobe Premiere Pro <= 15.4.1 Multiple Vulnerabilities (APSB21-100)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Premiere Pro installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Premiere Pro installed on the remote Windows host is prior to or equal to 15.4.1. It is, therefore, affected
by multiple vulnerabilities including the following:

  - Multiple arbitrary code execution vulnerabilities exist in Adobe Premiere Pro. An unauthenticated, 
    local attacker can exploit these to bypass authentication and execute arbitrary commands. 
    (CVE-2021-40792, CVE-2021-40793, CVE-2021-40794) 
  
  - Multiple denial of service (DoS) vulnerabilities exist in Adobe Premiere Pro. An unauthenticated, local 
    attacker can exploit this issue to cause the application to stop responding. (CVE-2021-40796, 
    CVE-2021-42263, CVE-2021-42264)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://helpx.adobe.com/security/products/premiere_pro/apsb21-100.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d714b70");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Premiere Pro version 22.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40794");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_pro");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_pro_cc");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_pro_installed.nasl");
  script_require_keys("installed_sw/Adobe Premiere Pro", "SMB/Registry/Enumerated");

  exit(0);
}
include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Premiere Pro', win_local:TRUE);

var constraints = [{'fixed_version': '15.4.2', 'fixed_display': '22.0'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
