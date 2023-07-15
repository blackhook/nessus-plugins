##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146448);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2021-21055");
  script_xref(name:"IAVA", value:"2021-A-0083");

  script_name(english:"Adobe Dreamweaver 20.2.x < 20.2.1 or 21.0.x < 21.1 Information disclosure (APSB21-13)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Dreamweaver installed on the remote Windows host is affected by a information disclosure
 vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dreamweaver installed on the remote Windows host is a version prior or equal to 20.2.1 or 21.1.
It is, therefore, affected by by an untrusted search path vulnerability that could result in information disclosure.
An attacker with physical access to the system could replace certain configuration files and dynamic libraries that
Dreamweaver references, potentially resulting in information disclosure.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb21-13.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dreamweaver 20.2.1 or 21.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21055");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:dreamweaver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_dreamweaver_installed.nasl");
  script_require_keys("installed_sw/Adobe Dreamweaver", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Dreamweaver');

constraints = [
  { 'min_version' : '20.2', 'fixed_version' : '20.2.1' },
  { 'min_version' : '21.0', 'fixed_version' : '21.1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
