##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163257);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/18");

  script_cve_id(
    "CVE-2021-34807",
    "CVE-2021-35207",
    "CVE-2021-35208",
    "CVE-2021-35209"
  );
  script_xref(name:"IAVA", value:"2022-A-0268-S");

  script_name(english:"Zimbra Collaboration Server 8.8.x < 8.8.15 Patch 23 / 9.0.0 < 9.0.0 Patch 16 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, Zimbra Collaboration Server is affected by a multiple vulnerabilities,
including the following:

  - An open redirect vulnerability exists in the /preauth Servlet in Zimbra Collaboration Suite through 9.0. 
    To exploit the vulnerability, an attacker would need to have obtained a valid zimbra auth token or a valid 
    preauth token. Once the token is obtained, an attacker could redirect a user to any URL via isredirect=1&redirectURL= 
    in conjunction with the token data (e.g., a valid authtoken= value). (CVE-2021-35207)

  - An issue was discovered in ZmMailMsgView.js in the Calendar Invite component in Zimbra Collaboration Suite 8.8.x 
    before 8.8.15 Patch 23. An attacker could place HTML containing executable JavaScript inside element attributes. 
    This markup becomes unescaped, causing arbitrary markup to be injected into the document. (CVE-2021-35208)

  - An issue was discovered in ProxyServlet.java in the /proxy servlet in Zimbra Collaboration Suite 8.8 before 
    8.8.15 Patch 23 and 9.x before 9.0.0 Patch 16. The value of the X-Host header overwrites the value of the Host 
    header in proxied requests. The value of X-Host header is not checked against the whitelist of hosts Zimbra is 
    allowed to proxy to (the zimbraProxyAllowedDomains setting). (CVE-2021-35209)

  - ap_escape_quotes() may write beyond the end of a buffer when given malicious input. No included modules
    pass untrusted data to these functions, but third-party / external modules may. This issue affects Apache
    HTTP Server 2.4.48 and earlier. (CVE-2021-34807)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P23");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/9.0.0/P16");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Security_Center");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.8.15 Patch 23, 9.0.0 Patch 16, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35209");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zimbra:collaboration_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zimbra_web_detect.nbin", "zimbra_nix_installed.nbin");
  script_require_keys("installed_sw/zimbra_zcs");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::zimbra::combined_get_app_info();

var constraints = [
  {'min_version':'8.8', 'max_version':'8.8.15', 'fixed_display':'8.8.15 Patch 23', 'Patch':'23'},
  {'min_version':'9.0', 'max_version':'9.0.0', 'fixed_display':'9.0.0 Patch 16', 'Patch':'16'}
];

vcf::zimbra::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
