##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(139230);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/10");

  script_cve_id("CVE-2020-3282");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs59840");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-cuc-imp-xss-OWuSYAp");
  script_xref(name:"IAVA", value:"2020-A-0297-S");

  script_name(english:"Cisco Unified Communications Manager IM & Presence Service Cross-Site Scripting (cisco-sa-cucm-cuc-imp-xss-OWuSYAp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager IM & Presence Service is affected by a
Cross-Site Scripting vulnerabilities. An remote attacker could exploit this vulnerability by inserting malicious data
into a specific data field in the web interface. A successful exploit could allow the attacker to execute arbitrary
script code in the context of the affected interface or access sensitive browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-cuc-imp-xss-OWuSYAp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef22b106");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs59840");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs59840");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3282");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_presence_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_cucm_imp_detect.nbin");
  script_require_keys("installed_sw/Cisco Unified CM IM&P");

  exit(0);
}

include('vcf.inc');

app = 'Cisco Unified CM IM&P';
get_kb_item_or_exit('installed_sw/' + app);

app_info = vcf::get_app_info(app:app);

constraints = [
  {'min_version' : '10.5.2', 'fixed_version' : '10.5.2.22900.12'},
  {'min_version' : '11.5.1', 'fixed_version' : '11.5.1.18900.15'},
  {'min_version' : '12.0.1', 'fixed_version' : '12.0.1.16574.1'},
  {'min_version' : '12.5.1', 'fixed_version' : '12.5.1.13000.17'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);

