#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140798);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/18");

  script_cve_id("CVE-2020-8246", "CVE-2020-8247");
  script_xref(name:"IAVA", value:"2020-A-0434-S");

  script_name(english:"Citrix SD-WAN WANOP Multiple Vulnerabilities (CTX281474)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix SD-WAN WANOP device is version 10.2.x prior to 10.2.7b, 11.0.x prior to 11.0.3f, 11.1.x prior to
11.1.2a, 11.2.x prior to 11.2.1a. It is, therefore, affected by multiple vulnerabilities:

  - A denial of service (DoS) vulnerability originating from the management network. (CVE-2020-8246)

  - A Escalation of privileges on the management interface. (CVE-2020-8247)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX281474");
  script_set_attribute(attribute:"solution", value:
"Upgrade Citrix SD-WAN WAN-OS to version 10.2.7b, 11.0.3f, 11.1.2a, 11.2.1a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8247");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(269, 400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:sd-wan");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_sdwan_detect.nbin");
  script_require_keys("installed_sw/Citrix SD-WAN");

  exit(0);
}

include('vcf.inc');

app_name = 'Citrix SD-WAN';
app_info = vcf::get_app_info(app:app_name);

edition = app_info['Edition'];
model = app_info['Model'];
pattern = "WAN-?OP";

if (report_paranoia < 2 && empty_or_null(edition) && empty_or_null(model))
  audit(AUDIT_PARANOID);

if (
	 !preg(pattern:pattern, string:edition) &&
     !preg(pattern:pattern, string:model) &&
     (!empty_or_null(edition) || !empty_or_null(model))
   )audit(AUDIT_HOST_NOT, 'affected');

constraints = [
  { 'min_version' : '10.2.0', 'fixed_version' : '10.2.7b' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.3f' },
  { 'min_version' : '11.1.0', 'fixed_version' : '11.1.2a' },
  { 'min_version' : '11.2.0', 'fixed_version' : '11.2.1a' }
];

vcf::check_version_and_report(
	app_info:app_info,
	constraints:constraints,
	severity:SECURITY_WARNING
);