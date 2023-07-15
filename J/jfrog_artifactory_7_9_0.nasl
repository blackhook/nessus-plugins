#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147721);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-1745");

  script_name(english:"JFrog < 7.9.0 File Inclusion Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"Determines if the remote JFrog Artifactory installation is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of JFrog Artifactory installed on the remote host is prior
to 7.9.0. It is affected by the following vulnerability:

  - A file inclusion vulnerability was found in the AJP connector enabled with a default AJP configuration port of 8009
    in Undertow version 2.0.29.Final and before and was fixed in 2.0.30.Final. A remote, unauthenticated attacker could 
    exploit this vulnerability to read web application files from a vulnerable server. In instances where the vulnerable 
    server allows file uploads, an attacker could upload malicious JavaServer Pages (JSP) code within a variety of file 
    types and trigger this vulnerability to gain remote code execution. (CVE-2020-1745)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.jfrog.com/confluence/display/JFROG/Fixed+Security+Vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dc55d3d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JFrog Artifactory 7.9.0, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jfrog:artifactory");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jfrog_artifactory_win_installed.nbin", "jfrog_artifactory_nix_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Artifactory");

  exit(0);
}

include('vcf.inc');

win_local = FALSE;
os = get_kb_item('Host/OS');
if ('windows' >< tolower(os)) win_local = TRUE;

app_info = vcf::get_app_info(app:'Artifactory', win_local:win_local);

constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.9.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
