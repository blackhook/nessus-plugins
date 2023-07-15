#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140192);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-8191",
    "CVE-2020-8193",
    "CVE-2020-8194",
    "CVE-2020-8195",
    "CVE-2020-8196",
    "CVE-2020-8198"
  );
  script_xref(name:"IAVA", value:"2020-A-0286-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0057");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");

  script_name(english:"Citrix SD-WAN WANOP 10.2.x Multiple Vulnerabilities (CTX276688)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix SD-WAN WANOP device is version 10.2.x prior to 10.2.7, 11.0.x prior to 11.0.3d, 11.1.x prior to
11.1.1a. It is, therefore, affected by multiple vulnerabilities:

  - An authorization bypass vulnerability exists in Citrix SD-WAN WANOP devices. An unauthenticated, remote
    attacker with access to the NSIP/management interface can exploit this issue to bypass authorization. 
    (CVE-2020-8193)

  - A code injection vulnerability exists in Citrix SD-WAN WANOP devices. An unauthenticated, remote attacker
    with access to the NSIP/management interface can exploit this issue to create a malicious file which, if
    executed by a victim on the management network, could allow the attacker arbitrary code execution in the
    context of that user. (CVE-2020-8194)

  - A cross-site scripting vulnerability exists in Citrix SD-WAN WANOP devices. An unauthenticated, remote
    attacker can exploit this issue by convincing a user to click a specially crafted URL, to execute
    arbitrary script code in a user's browser session. (CVE-2020-8191, CVE-2020-8198)

In addition, Citrix SD-WAN WANOP devices are also affected by several additional vulnerabilities including
configuration-dependent privilege escalations, information disclosures, and a denial of service (DoS) vulnerability.
Please refer to advisory CTX276688 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX276688");
  script_set_attribute(attribute:"solution", value:
"Upgrade Citrix SD-WAN WAN-OS to version 10.2.7, 11.0.3d 11.1.1a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8193");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:sd-wan");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (!preg(pattern:pattern, string:app_info['Edition']) && !preg(pattern:pattern, string:app_info['Model']))
  audit(AUDIT_HOST_NOT, 'affected');

constraints = [
  { 'min_version' : '10.2.0', 'fixed_version' : '10.2.7' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.3d' },
  { 'min_version' : '11.1.0', 'fixed_version' : '11.1.1a' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);


