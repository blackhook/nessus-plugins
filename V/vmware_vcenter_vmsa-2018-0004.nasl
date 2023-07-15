#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105784);
  script_version("1.8");
  script_cvs_date("Date: 2019/07/11 12:05:35");

  script_cve_id("CVE-2017-5715");
  script_bugtraq_id(102376);
  script_xref(name:"VMSA", value:"2018-0004");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"VMware vCenter Server 5.5.x < 5.5U3g / 6.0.x < 6.0U3d / 6.5.x < 6.5U1e Hypervisor-Assisted Guest Remediation (VMSA-2018-0004) (Spectre)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security patch which enables
hardware support for branch target mitigation.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is
5.5.x prior to 5.5U3g, 6.0.x prior to 6.0U3d, or 6.5.x prior to
6.5U1e. It is, therefore, missing security updates that add
hypervisor-assisted guest remediation for a speculative execution
vulnerability (CVE-2017-5715).");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0004.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/52085");
  script_set_attribute(attribute:"see_also", value:"https://spectreattack.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server version 5.5.U3g
(5.5.0 build-7460778) / 6.0U3d (6.0.0 build-7464194) /
6.5U1e (6.5.0 build-7515524) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (version =~ '^VMware vCenter 5\\.5$' && int(build) < 7450865) fixversion = '5.5.0 build-7460778';
else if (version =~ '^VMware vCenter 6\\.0$' && int(build) < 7462484) fixversion = '6.0.0 build-7464194';
else if(version =~ '^VMWare vCenter 6\\.5$' && int(build) < 7515524) fixversion = '6.5.0 build-7515524';
else audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

report = report_items_str(
  report_items:make_array(
    "Installed version", release,
    "Fixed version", fixversion
  ),
  ordered_fields:make_list("Installed version", "Fixed version")
);
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
