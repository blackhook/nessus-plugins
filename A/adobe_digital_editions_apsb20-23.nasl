#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135695);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/16");

  script_cve_id("CVE-2020-3798");
  script_xref(name:"IAVA", value:"2020-A-0163-S");

  script_name(english:"Adobe Digital Editions <= 4.5.11.187212 Information Disclosure (APSB20-23)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote Windows host is prior to 4.5.11. It is, therefore,
affected by an information disclosure vulnerability. An attacker can exploit this vulnerability to gain
unauthorized access to sensitive information via the enumeration of files.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb20-23.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dcb154a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.11.187303 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3798");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_digital_editions_installed.nbin");
  script_require_keys("installed_sw/Adobe Digital Editions", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Digital Editions', win_local:TRUE);

constraints = [
  { 'max_version':'4.5.11.187212', 'fixed_version' : '4.5.11.187303' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
