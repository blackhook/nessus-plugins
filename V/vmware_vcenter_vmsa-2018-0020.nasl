#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111760);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2018-3646");
  script_bugtraq_id(105080);
  script_xref(name:"VMSA", value:"2018-0020");

  script_name(english:"VMware vCenter Server 5.5.x / 6.0.x / 6.5.x / 6.7.x Speculative Execution Side Channel Vulnerability (Foreshadow) (VMSA-2018-0020)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host
is affected by a speculative execution side channel vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is
5.5.x prior to 5.5u3j, 6.0.x prior to 6.0u3h, 6.5.x prior to 6.5u2c,
or 6.7.x prior to 6.7.0d. It is, therefore, affected by a speculative
execution side channel attack known as L1 Terminal Fault (L1TF). An
attacker who successfully exploited L1TF may be able to read
privileged data across trust boundaries.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0020.html");
  script_set_attribute(attribute:"see_also", value:"https://foreshadowattack.eu/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the version, or later, referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3646");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if(version =~ '^VMWare vCenter 5\\.5$' && int(build) < 9313450) fixversion = '5.5.0 build-9313450';
else if(version =~ '^VMWare vCenter 6\\.0$' && int(build) < 9291058) fixversion = '6.0.0 build-9291058';
else if(version =~ '^VMWare vCenter 6\\.5$' && int(build) < 9451637) fixversion = '6.5.0 build-9451637';
else if(version =~ '^VMWare vCenter 6\\.7$' && int(build) < 9451876) fixversion = '6.7.0 build-9451876';
else audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

report = report_items_str(
  report_items:make_array(
    "Installed version", release,
    "Fixed version", fixversion
  ),
  ordered_fields:make_list("Installed version", "Fixed version")
);
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
