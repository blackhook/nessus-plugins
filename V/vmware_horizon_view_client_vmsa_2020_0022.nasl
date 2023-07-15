##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141803);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/26");

  script_cve_id("CVE-2020-3991");
  script_xref(name:"VMSA", value:"2020-0022");
  script_xref(name:"IAVA", value:"2020-A-0471");

  script_name(english:"VMware Horizon View Client < 5.5.0 DoS (VMSA-2020-0022)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon Client for Windows installed on the remote host is less than 5.5.0. It is, therefore,
affected by a denial of service (DoS) vulnerability due to a file system access control issue during install time. An
unauthenticated, local attacker can exploit this, via symbolic links, to overwrite certain admin privileged files
causing a denial of service condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0022.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMWare Horizon View Client 5.5.0 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3991");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view_client");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_horizon_view_client_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Horizon View Client");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'VMware Horizon View Client', win_local:TRUE);

constraints = [{ 'fixed_version' : '5.5.0' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
