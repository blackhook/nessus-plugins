#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135673);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/21");

  script_cve_id("CVE-2019-3762");
  script_xref(name:"IAVB", value:"2020-B-0014");

  script_name(english:"Dell EMC Data Protection Central 1.0, 1.0.1, 18.1, 18.2, 19.1 Improper Certificate Chain of Trust (DSA-2019-135)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Dell EMC Data Protection Central installed on the remote host is affected by an improper certificate
chain of trust vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Dell EMC Data Protection Central hosted on the remote web
server is 1.0, 1.0.1, 18.1, 18.2 or 19.1. It is, therefore, affected by an improper certificate chain of trust
vulnerability. An unauthenticated, remote attacker can exploit this, by obtaining a CA signed certificate from Data 
Protection Central to impersonate a valid system to compromise the integrity of data.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/security/en-ie/details/537007/DSA-2019-135-Dell-EMC-Data-Protection-Central-Improper-Chain-of-Trust-Vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f72a7f5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell EMC Data Protection Central version 18.2.1, 19.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3762");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:dell:emc_data_protection_central");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_emc_data_protection_central_web_detect.nbin");
  script_require_keys("installed_sw/Dell EMC Data Protection Central");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Dell EMC Data Protection Central');

constraints = [
  { 'min_version' : '1.0', 'max_version' : '1.0.1', 'fixed_display' : '18.2.1, 19.1.1 or later.' },
  { 'min_version' : '18.1', 'fixed_version' : '18.2.1' },
  { 'min_version' : '19.1', 'fixed_version' : '19.1.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
