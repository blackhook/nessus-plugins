#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86124);
  script_version("1.12");
  script_cvs_date("Date: 2019/09/24 15:02:54");

  script_cve_id("CVE-2015-6932");
  script_xref(name:"VMSA", value:"2015-0006");

  script_name(english:"VMware vCenter 5.5 LDAP Certificate Validation MitM Spoofing (VMSA-2015-0006)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization management application installed
that is affected by a man-in-the-middle spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware vCenter Server installed on the remote host is version 5.5
prior to 5.5u3. It is, therefore, affected by a man-in-the-middle
spoofing vulnerability due to improper validation of X.509
certificates from TLS LDAP servers. A remote, man-in-the-middle
attacker can exploit this to intercept network traffic by spoofing a
TLS server via a crafted certificate, resulting in the manipulation or
disclosure of sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0006.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 5.5u3 (5.5.0 build-3000241) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2019 Tenable Network Security, Inc.");

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
if (version =~ '^VMware vCenter 5\\.5$' && int(build) < 3000241) fixversion = '5.5.0 build-3000241';
else audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + release +
    '\n  Fixed version     : ' + fixversion +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
