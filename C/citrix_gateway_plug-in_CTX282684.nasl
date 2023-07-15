##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142019);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/18");

  script_cve_id("CVE-2020-8257", "CVE-2020-8258");
  script_xref(name:"IAVA", value:"2020-A-0434-S");

  script_name(english:"Citrix Gateway Plug-in for Windows 12.1.x < 12.1.59.16 / 13.0.x < 13.0.64.35 Multiple Vulnerabilities (CTX282684)");

  script_set_attribute(attribute:"synopsis", value:
"Citrix Gateway Plug-in for Windows installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Gateway Plug-in for Windows is 12.1 prior to 12.1.59.16 or 13.0 prior to 13.0.64.35. It is,
therefore, affected by multiple vulnerabilities that, if exploited, can result in a local user escalating their
privilege level to SYSTEM.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX282684");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Gateway Plug-in for Windows version 12.1.59.16, 13.0.64.35, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:gateway_plug-in");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_gateway_plug-in_detect.nbin");
  script_require_keys("installed_sw/Citrix Gateway Plug-in", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Citrix Gateway Plug-in', win_local:TRUE);

constraints = [
  { 'min_version' : '12.1', 'fixed_version' : '12.1.59.16' },
  { 'min_version' : '13.0', 'fixed_version' : '13.0.64.35'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
