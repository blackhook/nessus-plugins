#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103377);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-4926");
  script_bugtraq_id(100844);
  script_xref(name:"VMSA", value:"2017-0015");

  script_name(english:"VMware vCenter Server 6.5.x < 6.5u1 H5 Client Stored XSS (VMSA-2017-0015)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host
is affected by a stored cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is
6.5.x prior to 6.5u1. It is, therefore, affected by a user-input
validation error related to the 'H5 Client' that allows stored
cross-site scripting (XSS) attacks.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0015.html");
  # https://docs.vmware.com/en/VMware-vSphere/6.5/rn/vsphere-vcenter-server-651-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66151123");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server version 6.5.0u1 (6.5.0
build-5973321) or later. Alternatively, apply the vendor-supplied
workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4926");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service.nasl", "os_fingerprint.nasl", "vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port    = get_kb_item_or_exit("Host/VMware/vCenter");
version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");

# Extract and verify the build number
build = ereg_replace(
  pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$',
  string:release, replace:"\1"
);

if (empty_or_null(build) || build !~ '^[0-9]+$')
  audit(AUDIT_UNKNOWN_BUILD, "VMware vCenter Server");

build      = int(build);
release    = release - 'VMware vCenter Server ';
fixversion = NULL;
os         = get_kb_item("Host/OS");

# Check version and build numbers
if (version =~ "^VMware vCenter 6\.5($|[^0-9])")
{
  # vCenter Server 6.5 Update 1 | 27 JULY 2017 | ISO Build 5973321
  # Standard
  fixbuild = 5973321;
  if (build < fixbuild) fixversion = '6.5.0 build-'+fixbuild;
}

if (isnull(fixversion))
  audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

report = report_items_str(
  report_items:make_array(
    "Installed version", release,
    "Fixed version", fixversion
  ),
  ordered_fields:make_list("Installed version", "Fixed version")
);
security_report_v4(port:port, severity:SECURITY_NOTE, extra:report, xss:TRUE);
