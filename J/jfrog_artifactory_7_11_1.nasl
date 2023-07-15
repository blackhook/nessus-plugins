#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144306);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2016-10750",
    "CVE-2017-7657",
    "CVE-2017-1000487",
    "CVE-2020-25649"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"JFrog < 7.11.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Determines if the remote JFrog Artifactory installation is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of JFrog Artifactory installed on the remote host is prior
to 7.11.1. It is, therefore, affected by multiple vulnerabilities:

  - A flaw was found in FasterXML Jackson Databind, where it did not have entity expansion secured properly.
    This flaw allows vulnerability to XML external entity (XXE) attacks. The highest threat from this vulnerability
    is data integrity. (CVE-2020-25649)
  
  - Plexus-utils before 3.0.16 is vulnerable to command injection because it does not correctly process the contents
    of double quoted strings. (CVE-2017-1000487)

  - In Eclipse Jetty, versions 9.2.x and older, 9.3.x (all configurations), and 9.4.x (non-default configuration
    with RFC2616 compliance enabled), transfer-encoding chunks are handled poorly. The chunk length parsing was
    vulnerable to an integer overflow. Thus a large chunk size could be interpreted as a smaller chunk size and
    content sent as chunk body could be interpreted as a pipelined request. If Jetty was deployed behind an
    intermediary that imposed some authorization and that intermediary allowed arbitrarily large chunks to be passed on
    unchanged, then this flaw could be used to bypass the authorization imposed by the intermediary as the fake
    pipelined request would not be interpreted by the intermediary as a request. (CVE-2017-7657)

  - In Hazelcast before 3.11, the cluster join procedure is vulnerable to remote code execution via Java
    deserialization. If an attacker can reach a listening Hazelcast instance with a crafted JoinRequest, and vulnerable
    classes exist in the classpath, the attacker can run arbitrary code. (CVE-2016-10750)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.jfrog.com/confluence/display/JFROG/Fixed+Security+Vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dc55d3d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JFrog Artifactory 7.11.1, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7657");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jfrog:artifactory");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '7.0', 'fixed_version' : '7.11.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
