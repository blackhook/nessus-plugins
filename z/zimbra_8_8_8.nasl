##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162412);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/21");

  script_cve_id("CVE-2018-6882");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/10");

  script_name(english:"Zimbra Collaboration Server < 8.6.0 P10 / 8.7 < 8.7.11 P1 / 8.8.x < 8.8.7 XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by an XSS vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, Zimbra Collaboration Server is affected by a cross-site scripting (XSS)
vulnerability in the ZmMailMsgView.getAttachmentLinkHtml function that allows remote attackers to inject arbitrary web
script or HTML via a Content-Location header in an email attachment.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.8");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.7");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.7.11/P1");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.6.0/P10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.6.0 Patch 10, 8.7.11 Patch 1, 8.8.7, 8.8.8 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6882");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zimbra:collaboration_suite");
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
include('debug.inc');

var app_info = vcf::zimbra::combined_get_app_info();

var constraints = [
  {'max_version':'8.6.0', 'Patch':'10', 'fixed_display':'8.6.0 Patch10'},
  {'min_version':'8.7', 'max_version':'8.7.11', 'Patch':'1', 'fixed_display':'8.7.11 Patch1'},
  {'min_version':'8.8', 'fixed_version':'8.8.7', 'fixed_display':'8.8.7 / 8.8.8'}
];

vcf::zimbra::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
