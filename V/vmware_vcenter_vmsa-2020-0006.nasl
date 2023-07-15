#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135411);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-3952");
  script_xref(name:"VMSA", value:"2020-0006");
  script_xref(name:"IAVA", value:"2020-A-0136-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0033");

  script_name(english:"VMware vCenter Server 6.7 Sensitive Information Disclosure Vulnerability (VMSA-2020-0006)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by a
sensitive information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is 6.7 prior
to U3F, and is, therefore, affected by an information disclosure vulnerability caused by
insufficient access controls in vmdir. This allows an attacker with network access to an 
affected vmdir deployment may be able to extract highly sensitive information. This information
can be used to compromise the vCenter Server or other services which depends on VMware directory 
service authentication. (CVE-2020-3952)
    
Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0006.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 6.7 U3F or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3952");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

port = get_kb_item_or_exit('Host/VMware/vCenter');
version = get_kb_item_or_exit('Host/VMware/version');
release = get_kb_item_or_exit('Host/VMware/release');

# Extract and verify the build number
build = ereg_replace(pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$', string:release, replace:"\1");
if (build !~ '^[0-9]+$') exit(1, 'Failed to extract the build number from the release string.');

release = release - 'VMware vCenter Server ';
fixversion = NULL;

# Check version and build numbers
# 6.7 U3 https://docs.vmware.com/en/VMware-vSphere/6.7/rn/vsphere-vcenter-server-67u3f-release-notes.html
if(version =~ '^VMWare vCenter 6\\.7$' && int(build) < 15976714) fixversion = '6.7.0 build-15976714';
else audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

report = report_items_str(
  report_items:make_array(
    'Installed version', release,
    'Fixed version', fixversion
  ),
  ordered_fields:make_list('Installed version', 'Fixed version')
);
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);

