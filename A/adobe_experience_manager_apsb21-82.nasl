#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153399);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-40711",
    "CVE-2021-40712",
    "CVE-2021-40713",
    "CVE-2021-40714"
  );
  script_xref(name:"IAVA", value:"2021-A-0418-S");

  script_name(english:"Adobe Experience Manager 6.5.0.0 < 6.5.10.0 Multiple Vulnerabilities (APSB21-82)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is prior to tested version. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb21-82 advisory.

  - Adobe Experience Manager version 6.5.9.0 (and earlier) is affected by a reflected Cross-Site Scripting
    (XSS) vulnerability via the accesskey parameter. If an attacker is able to convince a victim to visit a
    URL referencing a vulnerable page, malicious JavaScript content may be executed within the context of the
    victim's browser (CVE-2021-40714)

  - Adobe Experience Manager version 6.5.9.0 (and earlier) is affected by a stored XSS vulnerability when
    creating Content Fragments. An authenticated attacker can send a malformed POST request to achieve
    arbitrary code execution. Malicious JavaScript may be executed in a victims browser when they browse to
    the page containing the vulnerable field. (CVE-2021-40711)

  - Adobe Experience Manager version 6.5.9.0 (and earlier) is affected by a improper input validation
    vulnerability via the path parameter. An authenticated attacker can send a malformed POST request to
    achieve server-side denial of service. (CVE-2021-40712)

  - Adobe Experience Manager version 6.5.9.0 (and earlier) is affected by a improper certificate validation
    vulnerability in the cold storage component. If an attacker can achieve a man in the middle when the cold
    server establishes a new certificate, they would be able to harvest sensitive information.
    (CVE-2021-40713)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/79.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/295.html");
  # https://helpx.adobe.com/security/products/experience-manager/apsb21-82.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4321e544");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Experience Manager version 6.5.10.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40714");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 295);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/15");

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
  { 'min_version' : '6.5.0.0', 'fixed_version' : '6.5.10.0' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
