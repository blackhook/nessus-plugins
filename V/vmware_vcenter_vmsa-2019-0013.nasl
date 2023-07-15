#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129503);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id("CVE-2019-5531", "CVE-2019-5532", "CVE-2019-5534");
  script_xref(name:"VMSA", value:"2019-0013");
  script_xref(name:"IAVA", value:"2019-A-0344");

  script_name(english:"VMware vCenter Server 6.0 / 6.5 / 6.7 Multiple Vulnerabilities (VMSA-2019-0013)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is 6.0 prior to U3j, 6.5 prior to U3, or 6.7 prior
to U3, and is, therefore, affected by the following vulnerabilities:

  - An information disclosure vulnerability caused by
    insufficient session expiration. This allows an
    attacker with physical access or the ability to mimic
    a websocket connection to a user's browser to control a
    VM console after the user's session has expired or they
    have logged out. (CVE-2019-5531)

  - An information disclosure vulnerability caused by
    plain-text logging of virtual machine credentials
    through OVF. This allows an attacker with access to the
    log files which contain the vCenter OVF-properties of a
    virtual machine deployed from an OVF to view the
    credentials used to deploy the OVF, which typically
    belong to the root account of the virtual machine.
    (CVE-2019-5532)

  - An information disclosure vulnerability in virtual
    machines deployed from an OVF which could expose login
    information via the virtual machine's vAppConfig
    properties. An attacker with access to query the
    vAppConfig properties of a virtual machine deployed
    from an OVF can view the credentials used to deploy the
    OVC, which typically belong to the root account of the
    virtual machine. (CVE-2019-5534)
    
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0013.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 6.0 U3j, 6.5 U3, or 6.7 U3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5531");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5534");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
# 6.0 U3j https://docs.vmware.com/en/VMware-vSphere/6.0/rn/vsphere-vcenter-server-60u3j-release-notes.html
if(version =~ '^VMWare vCenter 6\\.0$' && int(build) < 14510545) fixversion = '6.0.0 build-14510545';
# 6.5 U3 https://docs.vmware.com/en/VMware-vSphere/6.5/rn/vsphere-vcenter-server-65u3-release-notes.html
else if(version =~ '^VMWare vCenter 6\\.5$' && int(build) < 14020092) fixversion = '6.5.0 build-14020092';
# 6.7 U3 https://docs.vmware.com/en/VMware-vSphere/6.7/rn/vsphere-vcenter-server-67u3-release-notes.html
else if(version =~ '^VMWare vCenter 6\\.7$' && int(build) < 14367737) fixversion = '6.7.0 build-14367737';
else audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

report = report_items_str(
  report_items:make_array(
    'Installed version', release,
    'Fixed version', fixversion
  ),
  ordered_fields:make_list('Installed version', 'Fixed version')
);
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
