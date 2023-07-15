#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164341);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id(
    "CVE-2022-2068",
    "CVE-2022-24407",
    "CVE-2022-37041",
    "CVE-2022-37042",
    "CVE-2022-37043"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/01");
  script_xref(name:"CEA-ID", value:"CEA-2023-0004");

  script_name(english:"Zimbra Collaboration Server 8.8.x < 8.8.15 Patch 33 / 9.0.0 < 9.0.0 Patch 26 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, Zimbra Collaboration Server is affected by a multiple vulnerabilities,
including the following:

  - An issue was discovered in ProxyServlet.java in the /proxy servlet in Zimbra Collaboration Suite (ZCS)
    8.8.15 and 9.0. The value of the X-Forwarded-Host header overwrites the value of the Host header in
    proxied requests. The value of X-Forwarded-Host header is not checked against the whitelist of hosts that
    ZCS is allowed to proxy to (the zimbraProxyAllowedDomains setting). (CVE-2022-37041)

  - Zimbra Collaboration Suite (ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive
    and extracts files from it. By bypassing authentication (i.e., not having an authtoken), an attacker can
    upload arbitrary files to the system, leading to directory traversal and remote code execution. NOTE: this
    issue exists because of an incomplete fix for CVE-2022-27925. (CVE-2022-37042)

  - An issue was discovered in the webmail component in Zimbra Collaboration Suite (ZCS) 8.8.15 and 9.0. When
    using preauth, CSRF tokens are not checked on some POST endpoints. Thus, when an authenticated user views
    an attacker-controlled page, a request will be sent to the application that appears to be intended. The
    CSRF token is omitted from the request, but the request still succeeds. (CVE-2022-37043)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P33");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/9.0.0/P26");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Security_Center");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/uscert/ncas/alerts/aa22-228a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.8.15 Patch 33, 9.0.0 Patch 26, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2068");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-37042");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Zip Path Traversal in Zimbra (mboximport) (CVE-2022-27925)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zimbra:collaboration_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zimbra_web_detect.nbin", "zimbra_nix_installed.nbin");
  script_require_keys("installed_sw/zimbra_zcs");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::zimbra::combined_get_app_info();

var constraints = [
  {'min_version':'8.8', 'max_version':'8.8.15', 'fixed_display':'8.8.15 Patch 33', 'Patch':'33'},
  {'min_version':'9.0', 'max_version':'9.0.0', 'fixed_display':'9.0.0 Patch 26', 'Patch':'26'}
];

vcf::zimbra::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xsrf':TRUE}
);
