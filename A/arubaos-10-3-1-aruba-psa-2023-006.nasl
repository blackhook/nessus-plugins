#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175413);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/15");

  script_cve_id(
    "CVE-2023-22787",
    "CVE-2023-22788",
    "CVE-2023-22789",
    "CVE-2023-22790",
    "CVE-2023-22791"
  );
  script_xref(name:"IAVA", value:"2023-A-0252");

  script_name(english:"ArubaOS 10.3.x < 10.3.1.1 Multiple Vulnerabilities (ARUBA-PSA-2023-006)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS installed on the remote host is affected by multiple vulnerabilities:

  - An unauthenticated Denial of Service (DoS) vulnerability exists in a service accessed via the PAPI protocol 
    provided by Aruba InstantOS and ArubaOS 10. Successful exploitation of this vulnerability results in the 
    ability to interrupt the normal operation of the affected access point. (CVE-2023-22787)

  - Multiple authenticated command injection vulnerabilities exist in the Aruba InstantOS and ArubaOS 10 command line
    interface. Successful exploitation of these vulnerabilities nresult in the ability to execute arbitrary commands 
    as a privileged user on the underlying operating system. (CVE-2023-22788, CVE-2023-22789, CVE-2023-22790)

  - A vulnerability exists in Aruba InstantOS and ArubaOS 10 where an edge-case combination of network configuration, 
    a specific WLAN environment and an attacker already possessing valid user credentials on that WLAN can lead to 
    sensitive information being disclosed via the WLAN. The scenarios in which this disclosure of potentially sensitive
    information can occur are complex and depend on factors that are beyond the control of the attacker. 
    (CVE-2023-22791)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2023-006.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the ArubaOS version mentioned in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22790");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:arubaos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arubaos_installed.nbin", "arubaos_detect.nbin");
  script_require_keys("installed_sw/ArubaOS");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::aruba::combined_get_app_info(os_flavour:'ArubaOS');
if (!empty_or_null(app_info.ver_model))
    audit(AUDIT_INST_VER_NOT_VULN, 'ArubaOS', app_info.version);

var constraints = [
    { 'min_version':'10.3', 'fixed_version':'10.3.1.1' }
  ];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);