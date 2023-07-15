#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(148449);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2021-1450");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw29572");
  script_xref(name:"CISCO-SA", value:"cisco-sa-anyconnect-dos-55AYyxYr");

  script_name(english:"MacOS: Cisco AnyConnect Secure Mobility Client DoS (cisco-sa-anyconnect-dos-55AYyxYr)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the interprocess communication (IPC) channel of Cisco AnyConnect Secure Mobility Client could allow
an authenticated, local attacker to cause a denial of service (DoS) condition on an affected device. To exploit this
vulnerability, the attacker would need to have valid credentials on the device. The vulnerability is due to
insufficient validation of user-supplied input. An attacker could exploit this vulnerability by sending one or more
crafted IPC messages to the AnyConnect process on an affected device. A successful exploit could allow the attacker to
stop the AnyConnect process, causing a DoS condition on the device. Note: The process under attack will automatically
restart so no action is needed by the user or admin.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-anyconnect-dos-55AYyxYr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ceee8aef");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw29572");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw29572");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1450");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_cisco_anyconnect_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "Host/MacOSX/Version");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/MacOSX/Version');

app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client');

constraints = [{ 'fixed_version' : '4.10.00093' }];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
