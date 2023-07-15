#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135297);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/25");

  script_cve_id("CVE-2020-5832");
  script_xref(name:"IAVA", value:"2020-A-0132");

  script_name(english:"Symantec Data Center Security Manager Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"Symantec Data Center Security Manager Component, with versions earlier than 6.8.2 (aka
6.8 MP2), are found to be susceptible to a privilege escalation vulnerability, where an 
attacker may attempt to compromise the software application to gain elevated access to 
resources that are normally protected from an application or user.");
  # https://support.broadcom.com/security-advisory/security-advisory-detail.html?notificationId=SYMSA1750
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f5d9e4e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Data Center Security Manager version 6.8.2 (aka 6.8 MP2), and apply
the protection policy modifications described in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5832");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:data_center_security");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_dcs_local_detect.nbin");
  script_require_keys("installed_sw/Symantec Data Center Security Server Manager");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::get_app_info(app:'Symantec Data Center Security Server Manager');
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
      { "fixed_version" : "6.8.2" }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
