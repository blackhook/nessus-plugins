#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139203);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/03");

  script_cve_id("CVE-2020-3974");
  script_xref(name:"VMSA", value:"2020-0017");
  script_xref(name:"IAVA", value:"2020-A-0265");

  script_name(english:"VMware Horizon View Client 5.x < 5.4.3 Privilege Escalation (VMSA-2020-0017) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"A desktop virtualization application installed on the remote macOS or Mac OS X host is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon View Client installed on the remote macOS or Mac OS X host is 5.x prior to 5.4.3. It is,
therefore, affected by a privilege escalation vulnerability in the service startup script due to improper XPC Client
validation. A local attacker with normal user privileges can escalate their privileges to root on the system.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0017.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Horizon View Client 5.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3974");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_vmware_horizon_view_client_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/VMware Horizon View Client");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'VMware Horizon View Client');

constraints = [
  { 'min_version' : '5', 'fixed_version' : '5.4.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
