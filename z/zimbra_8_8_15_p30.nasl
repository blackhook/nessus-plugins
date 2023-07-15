##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162410);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2022-24682");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/11");

  script_name(english:"Zimbra Collaboration Server 8.8.x < 8.8.15 Patch 30 XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by an XSS vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, Zimbra Collaboration Server is affected by a cross-site scripting (XSS)
vulnerability in the Calendar feature, as exploited in the wild starting in December 2021. An attacker can place HTML
containing executable JavaScript inside element attributes. This markup becomes unescaped, causing arbitrary markup to
be injected into the document.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P30");
  # https://blog.zimbra.com/2022/02/hotfix-available-5-feb-for-zero-day-exploit-vulnerability-in-zimbra-8-8-15/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e7aee47");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Security_Center");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.8.15 Patch 30 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24682");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/21");

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
  {'min_version':'8.8', 'max_version':'8.8.15', 'fixed_display':'8.8.15 Patch 30', 'Patch':'30'}
];

vcf::zimbra::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
