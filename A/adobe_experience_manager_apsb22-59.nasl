#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168696);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2022-30679",
    "CVE-2022-35693",
    "CVE-2022-35694",
    "CVE-2022-35695",
    "CVE-2022-35696",
    "CVE-2022-42345",
    "CVE-2022-42346",
    "CVE-2022-42348",
    "CVE-2022-42349",
    "CVE-2022-42350",
    "CVE-2022-42351",
    "CVE-2022-42352",
    "CVE-2022-42354",
    "CVE-2022-42356",
    "CVE-2022-42357",
    "CVE-2022-42360",
    "CVE-2022-42362",
    "CVE-2022-42364",
    "CVE-2022-42365",
    "CVE-2022-42366",
    "CVE-2022-42367",
    "CVE-2022-44462",
    "CVE-2022-44463",
    "CVE-2022-44465",
    "CVE-2022-44466",
    "CVE-2022-44467",
    "CVE-2022-44468",
    "CVE-2022-44469",
    "CVE-2022-44470",
    "CVE-2022-44471",
    "CVE-2022-44473",
    "CVE-2022-44474",
    "CVE-2022-44488",
    "CVE-2022-44510"
  );
  script_xref(name:"IAVA", value:"2022-A-0529-S");

  script_name(english:"Adobe Experience Manager 6.5.0.0 < 6.5.15.0 Multiple Vulnerabilities (APSB22-59)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is prior to 6.5.15.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB22-59 advisory.

  - AEM Forms Cloud Service offering, as well as version 6.5.10.0 (and below) are affected by an XML External
    Entity (XXE) injection vulnerability that could be abused by an attacker to achieve RCE. (CVE-2021-40722)

  - AEM's Cloud Service offering, as well as version 6.5.10.0 (and below) are affected by a dispatcher bypass
    vulnerability that could be abused to evade security controls. Sensitive areas of the web application may
    be exposed through exploitation of the vulnerability. (CVE-2021-43762)

  - Adobe Experience Manager versions 6.5.13.0 (and earlier) is affected by a reflected Cross-Site Scripting
    (XSS) vulnerability. If an attacker is able to convince a victim to visit a URL referencing a vulnerable
    page, malicious JavaScript content may be executed within the context of the victim's browser.
    Exploitation of this issue requires low-privilege access to AEM. (CVE-2022-28851, CVE-2022-38438,
    CVE-2022-38439)

  - Cross-site Scripting (XSS) (CWE-79) potentially leading to Arbitrary code execution (CVE-2022-30679,
    CVE-2022-35693, CVE-2022-35694, CVE-2022-35695, CVE-2022-35696, CVE-2022-42345, CVE-2022-42346,
    CVE-2022-42348, CVE-2022-42349, CVE-2022-42350, CVE-2022-42352, CVE-2022-42354, CVE-2022-42356,
    CVE-2022-42357, CVE-2022-42360, CVE-2022-42362, CVE-2022-42364, CVE-2022-42365, CVE-2022-42366,
    CVE-2022-42367, CVE-2022-44462, CVE-2022-44463, CVE-2022-44465, CVE-2022-44466, CVE-2022-44467,
    CVE-2022-44468, CVE-2022-44469, CVE-2022-44470, CVE-2022-44471, CVE-2022-44473, CVE-2022-44474)

  - Improper Access Control (CWE-284) potentially leading to Security feature bypass (CVE-2022-42351)

  - URL Redirection to Untrusted Site ('Open Redirect') (CWE-601) potentially leading to Security feature
    bypass (CVE-2022-44488)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb22-59.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ff15f91");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Experience Manager version 6.5.15.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44510");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 284, 601);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_experience_manager_http_detect.nbin");
  script_require_keys("installed_sw/Adobe Experience Manager");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:4502);
var app_info = vcf::get_app_info(app:'Adobe Experience Manager', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '6.5.0.0', 'fixed_version' : '6.5.15.0' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
