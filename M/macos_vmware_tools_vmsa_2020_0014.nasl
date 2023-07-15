#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137839);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id("CVE-2020-3972");
  script_xref(name:"IAVB", value:"2020-B-0033");
  script_xref(name:"VMSA", value:"2020-0014");

  script_name(english:"VMware Tools < 11.1.1 Denial-of-Service Vulnerability (VMSA-2020-0014) (macOS)");
  script_summary(english:"Checks the VMware Tools version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote MacOS / MacOSX host is affected
by a denial-of-service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote MacOS/MacOSX host
is prior to 11.1.1. It is, therefore, affected by a denial-of-service vulnerability in 
the Host-Guest File System (HGFS) implementation. Successful exploitation of this issue 
may allow attackers with non-admin privileges on guest macOS virtual machines to create 
a denial-of-service condition on their own VMs.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0014.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMwware Tools version 11.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3972");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:tools");
  script_set_attribute(attribute:"stig_severity", value:"III");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_vmware_tools_installed.nbin");
  script_require_keys("installed_sw/VMware Tools", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/MacOSX/Version');

app_info = vcf::get_app_info(app:'VMware Tools');

constraints = [{ 'fixed_version' : '11.1.1' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
