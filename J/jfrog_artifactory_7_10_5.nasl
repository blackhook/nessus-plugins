#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144301);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-17359", "CVE-2020-7226");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"JFrog Artifactory < 7.10.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Determines if the remote JFrog Artifactory installation is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of JFrog Artifactory installed on the remote machine is
prior to 7.10.5. It is, therefore, affected by multiple vulnerabilities:

  - CiphertextHeader.java in Cryptacular 1.2.3, as used in Apereo CAS and other products, allows attackers to
    trigger excessive memory allocation during a decode operation, because the nonce array length associated with
    'new byte' may depend on untrusted input within the header of encoded data. (CVE-2020-7226)
  
  - The ASN.1 parser in Bouncy Castle Crypto (aka BC Java) 1.63 can trigger a large attempted memory allocation,
    and resultant OutOfMemoryError error, via crafted ASN.1 data. This is fixed in 1.64. (CVE-2019-17359)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.jfrog.com/confluence/display/JFROG/Fixed+Security+Vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dc55d3d");
  script_set_attribute(attribute:"solution", value:
"Update to JFrog Artifactory 7.10.5, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7226");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/24");
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
  { 'min_version' : '7.0', 'fixed_version' : '7.10.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
