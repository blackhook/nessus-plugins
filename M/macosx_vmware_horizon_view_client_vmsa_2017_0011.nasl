#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100839);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/20");

  script_cve_id("CVE-2017-4918");
  script_bugtraq_id(98984);
  script_xref(name:"VMSA", value:"2017-0011");

  script_name(english:"VMware Horizon View Client 2.x / 3.x / 4.x < 4.5.0 Startup Script Command Injection (VMSA-2017-0011) (macOS)");
  script_summary(english:"Checks the VMware Horizon View Client version.");

  script_set_attribute(attribute:"synopsis", value:
"A desktop virtualization application installed on the remote macOS or
Mac OS X host is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon View Client installed on the remote
macOS or Mac OS X host is 2.x, 3.x, or 4.x prior to 4.5.0. It is,
therefore, affected by a command injection vulnerability in the
service startup script due to improper validation of user-supplied
input. A local attacker can exploit this, by sending specially crafted
data, to inject and execute arbitrary commands with root privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0011");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Horizon View Client 4.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4918");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_vmware_horizon_view_client_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/VMware Horizon View Client");

  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"VMware Horizon View Client");

constraints = [{ "min_version" : "2", "fixed_version" : "4.5.0" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
