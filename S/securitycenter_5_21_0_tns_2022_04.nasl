##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160883);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2021-24785",
    "CVE-2021-41116",
    "CVE-2021-41182",
    "CVE-2021-41183",
    "CVE-2021-41184",
    "CVE-2022-21707",
    "CVE-2022-24828"
  );

  script_name(english:"Tenable SecurityCenter < 5.21.0 Multiple Vulnerabilities (TNS-2022-09)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is less 
than 5.21.0 and is therefore affected by multiple vulnerabilities:

    - A command injection vulnerability exists in Composer. An unauthenticated, remote attacker can exploit this
      to execute arbitrary commands by installing untrusted dependencies. (CVE-2021-41116)
    
    - A code injection vulnerability exists in Composer. An unauthenticated, remote attacker can exploit this
      to execute arbitrary commands by controlling the $file or $identifier argument. (CVE-2022-24828)
    
    - Read/write beyond bounds - Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to
      overwrite heap memory with possibly attacker provided data. This issue affects Apache HTTP Server 2.4 version 
      2.4.52 and prior versions. (CVE-2022-23943)
  
Note that successful exploitation of the most serious issues can result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-09");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory or upgrade to 5.21.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41116");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::tenable_sc::get_app_info();

var constraints = [
  { 'min_version' : '5.12.0', 'max_version': '5.20', 'fixed_display' : 'Upgrade to 5.21.0 or later'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
