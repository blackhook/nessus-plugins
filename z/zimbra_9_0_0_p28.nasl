#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168269);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/06");

  script_cve_id("CVE-2022-20770", "CVE-2022-20771", "CVE-2022-26377");
  script_xref(name:"IAVA", value:"2022-A-0498-S");

  script_name(english:"Zimbra Collaboration Server 8.8.x < 8.8.15 Patch 35 / 9.0.0 < 9.0.0 Patch 28 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, Zimbra Collaboration Server is affected by a multiple vulnerabilities,
as follows:

  - A vulnerability in the ClamAV package: On April 20, 2022, the following vulnerability in the ClamAV
    scanning library versions 0.103.5 and earlier and 0.104.2 and earlier was disclosed: A vulnerability in
    the TIFF file parser of Clam AntiVirus (ClamAV) versions 0.104.0 through 0.104.2 and LTS version 0.103.5
    and prior versions could allow an unauthenticated, remote attacker to cause a denial of service condition
    on an affected device. (CVE-2022-20771)

  - A vulnerability in the ClamAV package: On April 20, 2022, the following vulnerability in the ClamAV
    scanning library versions 0.103.5 and earlier and 0.104.2 and earlier was disclosed: A vulnerability in
    CHM file parser of Clam AntiVirus (ClamAV) versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
    prior versions could allow an unauthenticated, remote attacker to cause a denial of service condition on
    an affected device. (CVE-2022-20770)

  - A vulnerability in the Apache package: Inconsistent Interpretation of HTTP Requests ('HTTP Request
    Smuggling') vulnerability in mod_proxy_ajp of Apache HTTP Server allows an attacker to smuggle requests to
    the AJP server it forwards requests to. This issue affects Apache HTTP Server Apache HTTP Server 2.4
    version 2.4.53 and prior versions. (CVE-2022-26377)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P35");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/9.0.0/P28");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Security_Center");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.8.15 Patch 35, 9.0.0 Patch 28, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/29");

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
  {'min_version':'8.8', 'max_version':'8.8.15', 'fixed_display':'8.8.15 Patch 35', 'Patch':'35'},
  {'min_version':'9.0', 'max_version':'9.0.0', 'fixed_display':'9.0.0 Patch 28', 'Patch':'28'}
];

vcf::zimbra::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
