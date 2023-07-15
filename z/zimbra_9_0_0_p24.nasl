##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163072);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-21702",
    "CVE-2021-39275",
    "CVE-2021-40438",
    "CVE-2022-27924",
    "CVE-2022-27925",
    "CVE-2022-27926"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/15");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/01");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/24");
  script_xref(name:"IAVA", value:"2022-A-0268-S");
  script_xref(name:"CEA-ID", value:"CEA-2023-0004");

  script_name(english:"Zimbra Collaboration Server 8.8.x < 8.8.15 Patch 31 / 9.0.0 < 9.0.0 Patch 24 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, Zimbra Collaboration Server is affected by a multiple vulnerabilities,
including the following:

  - A vulnerability that allows an unauthenticated attacker to inject arbitrary memcache commands into a
    targeted instance. These memcache commands becomes unescaped, causing an overwrite of arbitrary cached
    entries. (CVE-2022-27924)

  - Zimbra Collaboration (aka ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and
    extracts files from it. An authenticated user with administrator rights has the ability to upload
    arbitrary files to the system, leading to directory traversal. (CVE-2022-27925)

  - A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the
    remote user. This issue affects Apache HTTP Server 2.4.48 and earlier. (CVE-2021-40438)

  - ap_escape_quotes() may write beyond the end of a buffer when given malicious input. No included modules
    pass untrusted data to these functions, but third-party / external modules may. This issue affects Apache
    HTTP Server 2.4.48 and earlier. (CVE-2021-39275)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P31");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/9.0.0/P24");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Security_Center");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.8.15 Patch 31, 9.0.0 Patch 24, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39275");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Zip Path Traversal in Zimbra (mboximport) (CVE-2022-27925)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zimbra:collaboration_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  {'min_version':'8.8', 'max_version':'8.8.15', 'fixed_display':'8.8.15 Patch 31', 'Patch':'31'},
  {'min_version':'9.0', 'max_version':'9.0.0', 'fixed_display':'9.0.0 Patch 24', 'Patch':'24'}
];

vcf::zimbra::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
