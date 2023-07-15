#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123521);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2018-0391");
  script_bugtraq_id(104942);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd86586");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180801-pcp-dos");

  script_name(english:"Cisco Prime Collaboration Provisioning Unauthorized Password Change Denial of Service Vulnerability (cisco-sa-20180801-pcp-dos");
  script_summary(english:"Checks the Cisco Prime Collaboration Provisioning version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management server is affected by a hard-coded
password vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Cisco Prime
Collaboration Provisioning server is prior to 12.3. It is, therefore,
affected by unauthorized password change denial of service vulnerability
which could allow the attacker to cause the affected device to become
inoperable, resulting in a denial of service (DoS) condition.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180801-pcp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5816f01");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Provisioning version 12.3 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0391");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_provisioning");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_collaboration_provisioning_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationProvisioning/version");

  exit(0);
}

include("vcf.inc");

app = "Prime Collaboration Provisioning";

app_info = vcf::get_app_info(app:app, kb_ver:"Host/Cisco/PrimeCollaborationProvisioning/version");

constraints = [
  { "min_version" : "1.0", "max_version" : "12.2", "fixed_version" : "12.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

