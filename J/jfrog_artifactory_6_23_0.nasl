#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147722);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-18640",
    "CVE-2019-12402",
    "CVE-2019-20104",
    "CVE-2020-7692",
    "CVE-2020-15586"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"JFrog < 6.23.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Determines if the remote JFrog Artifactory installation is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of JFrog Artifactory installed on the remote host is prior
to 6.23.0. It is, therefore, affected by multiple vulnerabilities:

  - The Alias feature in SnakeYAML 1.18 allows entity expansion during a load operation. (CVE-2017-18640)

  - The file name encoding algorithm used internally in Apache Commons Compress 1.15 to 1.18 can get into an infinite
    loop when faced with specially crafted inputs. This can lead to a denial of service attack if an attacker can choose
    the file names inside of an archive created by Compress. (CVE-2019-12402)

  - The OpenID client application in Atlassian Crowd before version 3.6.2, and from version 3.7.0 before 3.7.1
    allows remote attackers to perform a Denial of Service attack via an XML Entity Expansion vulnerability. (CVE-2019-20104)

  - Go before 1.13.13 and 1.14.x before 1.14.5 has a data race in some net/http servers, as demonstrated by the
    httputil.ReverseProxy Handler, because it reads a request body and writes a response at the same time. (CVE-2020-15586)

  - PKCE support is not implemented in accordance with the RFC for OAuth 2.0 for Native Apps. Without the use of PKCE, 
    an attacker is able to obtain the authorization code using a malicious app on the client-side and use it to gain 
    authorization to the protected resource. (CVE-2020-7692)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.jfrog.com/confluence/display/JFROG/Fixed+Security+Vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dc55d3d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JFrog Artifactory 6.23.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7692");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/10");
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
  { 'min_version' : '0.0', 'fixed_version' : '6.23.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
