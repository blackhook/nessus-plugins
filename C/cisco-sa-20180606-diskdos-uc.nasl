#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130017);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/18 23:14:14");

  script_cve_id("CVE-2017-6779");
  script_bugtraq_id(104662);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf64332");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180606-diskdos");

  script_name(english:"Cisco Unity Connection libSRTP Denial of Service Vulnerability");
  script_summary(english:"Checks the Cisco Unity Connection version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in local file management for Cisco Unity Connection could allow an unauthenticated,
remote attacker to cause high disk utilization, resulting in a denial of service (DoS) condition.
The vulnerability occurs because a certain system log file does not have a maximum size restriction.
Therefore, the file is allowed to consume the majority of available disk space on the appliance.
An attacker could exploit this vulnerability by sending crafted remote connection requests to the
appliance. Successful exploitation could allow the attacker to increase the size of a system log file
so that it consumes most of the disk space. The lack of available disk space could lead to a DoS
condition in which the application functions could operate abnormally, making the appliance unstable.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-diskdos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6ab2b07");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf64332");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCvf64332");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6779");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_uc_version.nasl");
  script_require_keys("installed_sw/Cisco VOSS Unity");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco VOSS Unity');

constraints = [
  { 'fixed_version':'10.5.2.15900.8', 'fixed_display':'10.5(2)SU5' },
  { 'min_version':'11.0', 'fixed_version':'11.5.1.11900.26', 'fixed_display':'11.5.1SU3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
