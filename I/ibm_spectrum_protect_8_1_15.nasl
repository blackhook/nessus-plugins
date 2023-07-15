#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(163633);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-22487", "CVE-2022-22496");

  script_name(english:"IBM Spectrum Protect 8.1.0.000 < 8.1.15.000 Multiple Vulnerabilites");

  script_set_attribute(attribute:"synopsis", value:
"The backup service installed on the remote host is affected by multiple vulnerabilites.");
  script_set_attribute(attribute:"description", value:
"IBM Spectrum Protect, formerly known as Tivoli Storage Manager,
running on the remote host is version 8.1.0.000 < 8.1.15.000. It is, therefore, is vulnerable to both:

  - An offline dictionary attack (CVE-2022-22496) while a user account is being established for
    the IBM Spectrum Protect server if SESSIONSECURITY=TRANSITIONAL is configured. 
  
  - An unauthorized access vulnerability (CVE-2022-22487) where an IBM Spectrum Protect storage agent
    can allow a remote attacker to perform a brute force attack with unlimited login attempts without 
    locking the administrative ID. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6596881");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Spectrum Protect 8.1.15.000 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22487");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:spectrum_protect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_tsm_detect.nasl", "ibm_spectrum_protect_installed.nbin");
  script_require_ports("installed_sw/IBM Tivoli Storage Manager", "installed_sw/IBM Spectrum Protect");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

port = get_service(svc:'tsm-agent');

app_info = vcf::ibm::spectrum_protect::get_app_info(port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '8.1.0', 'fixed_version' : '8.1.15' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);