#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(106950);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id("CVE-2017-5753", "CVE-2017-5754");
  script_bugtraq_id(102371, 102378);
  script_xref(name:"VMSA", value:"2018-0007");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"IAVA", value:"2018-A-0062-S");

  script_name(english:"VMware vCenter Server 6.5.x < 6.5u1f Multiple Vulnerabilities (VMSA-2018-0007) (Spectre-1) (Meltdown)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is
6.5.x prior to 6.5u1f. It is, therefore, affected by multiple
vulnerabilities. See advisory for details.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0007.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server version
6.5u1f (6.5.0 build-7801515) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2023 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item_or_exit("Host/VMware/vCenter");
version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");

# Extract and verify the build number
build = ereg_replace(pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$', string:release, replace:"\1");
if (build !~ '^[0-9]+$') exit(1, 'Failed to extract the build number from the release string.');

release = release - 'VMware vCenter Server ';
fixversion = NULL;

# Check version and build numbers
if(version =~ '^VMWare vCenter 6\\.5$' && int(build) < 7801515) fixversion = '6.5.0 build-7801515';
else audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

report = report_items_str(
  report_items:make_array(
    "Installed version", release,
    "Fixed version", fixversion
  ),
  ordered_fields:make_list("Installed version", "Fixed version")
);
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
