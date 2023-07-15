#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136283);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/17");

  script_cve_id(
    "CVE-2020-7110",
    "CVE-2020-7111",
    "CVE-2020-7113",
    "CVE-2020-7114"
  );
  script_xref(name:"IAVA", value:"2020-A-0178-S");

  script_name(english:"Aruba Networks ClearPass Policy Manager 6.7.x < 6.7.13 / 6.8.x < 6.8.4 Multiple Vulnerabilities (ARUBA-PSA-2020-004)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host running Aruba Networks (HP) Clearpass Policy Manager is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is Aruba Networks (HP) Clearpass Policy Manager
version 6.7.x prior to 6.7.13, or 6.8.x prior to 6.8.4. It is,
therefore, vulnerable to multiple security vulnerabilities as
described in the vendor advisory ARUBA-PSA-2020-004.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2020-004.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Aruba Networks (HP) Clearpass Policy Manager version 6.7.13 / 6.8.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7114");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:arubanetworks:clearpass");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("aruba_clearpass_polman_detect.nbin");
  script_require_keys("Host/Aruba_Clearpass_Policy_Manager/version");

  exit(0);
}

include('vcf.inc');

app = 'Aruba ClearPass Policy Manager';

app_info = vcf::get_app_info(app:app, kb_ver:"Host/Aruba_Clearpass_Policy_Manager/version");

constraints = [
  { 'min_version' : '6.7.0', 'fixed_version' : '6.7.13' },
  { 'min_version' : '6.8.0', 'fixed_version' : '6.8.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
