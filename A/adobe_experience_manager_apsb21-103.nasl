#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156060);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/19");

  script_cve_id(
    "CVE-2021-40711",
    "CVE-2021-40712",
    "CVE-2021-40722",
    "CVE-2021-42725",
    "CVE-2021-43761",
    "CVE-2021-43762",
    "CVE-2021-43764",
    "CVE-2021-43765",
    "CVE-2021-44176",
    "CVE-2021-44177",
    "CVE-2021-44178"
  );
  script_xref(name:"IAVA", value:"2021-A-0585-S");

  script_name(english:"Adobe Experience Manager 6.5.0.0 < 6.5.11.0 Multiple Vulnerabilities (APSB21-103)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is prior to tested version. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb21-103 advisory.

  - AEM Forms Cloud Service offering, as well as version 6.5.10.0 (and below) are affected by an XML External
    Entity (XXE) injection vulnerability that could be abused by an attacker to achieve RCE. (CVE-2021-40722)

  - Adobe Experience Manager version 6.5.9.0 (and earlier) is affected by a stored XSS vulnerability when
    creating Content Fragments. An authenticated attacker can send a malformed POST request to achieve
    arbitrary code execution. Malicious JavaScript may be executed in a victim's browser when they browse to
    the page containing the vulnerable field. (CVE-2021-40711)

  - Adobe Experience Manager version 6.5.9.0 (and earlier) is affected by a improper input validation
    vulnerability via the path parameter. An authenticated attacker can send a malformed POST request to
    achieve server-side denial of service. (CVE-2021-40712)

  - Adobe Experience Manager version 6.5.9.0 (and earlier) are affected by an improper access control
    vulnerability that leads to a security feature bypass. By manipulating referer headers, an unauthenticated
    attacker could gain access to arbitrary pages that they are not authorized to access. (CVE-2021-42725)

  - AEM's Cloud Service offering, as well as versions 6.5.7.0 (and below), 6.4.8.3 (and below) and 6.3.3.8
    (and below) are affected by a stored Cross-Site Scripting (XSS) vulnerability that could be abused by an
    attacker to inject malicious scripts into vulnerable form fields. Malicious JavaScript may be executed in
    a victim's browser when they browse to the page containing the vulnerable field. (CVE-2021-43761)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/79.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/611.html");
  # https://helpx.adobe.com/security/products/experience-manager/apsb21-103.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29bb3f13");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Experience Manager version 6.5.11.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40722");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 611);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '6.5.0.0', 'fixed_version' : '6.5.11.0' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
