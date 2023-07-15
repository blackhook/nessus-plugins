#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151976);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-35999", "CVE-2021-36007");
  script_xref(name:"IAVA", value:"2021-A-0341-S");

  script_name(english:"Adobe Prelude < 10.1 Arbitrary Code Execution Vulnerabilities (APSB21-58)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by arbitrary code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Prelude CC installed on the remote Windows host is prior to 10.1. It is, therefore, affected by
multiple arbitrary code execution vulnerabilities due to insufficient input validation. An unauthenticated, remote 
attacker can exploit this to bypass authentication and execute arbitrary commands. 

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's 
self-reported version number.");
  # https://helpx.adobe.com/security/products/prelude/apsb21-58.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d7f9993");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Prelude version 10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35999");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:prelude");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_prelude_installed.nasl");
  script_require_keys("installed_sw/Adobe Prelude", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Prelude', win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [{'fixed_version': '10.1'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
