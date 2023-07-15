##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148656);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2020-3556");
  script_xref(name:"IAVA", value:"2020-A-0505-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv30103");
  script_xref(name:"CISCO-SA", value:"cisco-sa-anyconnect-ipc-KfQO9QhK");

  script_name(english:"MacOSX: Cisco AnyConnect Secure Mobility Client Arbitrary Code Execution (cisco-sa-anyconnect-ipc-KfQO9QhK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco AnyConnect Secure Mobility Client is affected by a arbitrary code
execution vulnerability. The vulnerability is due to a lack of authentication to the IPC listener. An authenticated,
local attacker could exploit this vulnerability by sending crafted IPC messages to the AnyConnect client IPC listener.
A successful exploit could allow an attacker to cause the targeted AnyConnect user to execute a malicious script. This
script would execute with the privileges of the targeted AnyConnect user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-anyconnect-ipc-KfQO9QhK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?601e2110");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv30103");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv30103");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3556");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_cisco_anyconnect_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "Host/MacOSX/Version", "Host/local_checks_enabled", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/MacOSX/Version')) audit(AUDIT_OS_NOT, 'Mac OS X');
if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# We cannot test for the full vulnerable condition
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client');

constraints = [{ 'max_version' : '4.10.0', 'fixed_display' : 'See vendor advisory' }];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
