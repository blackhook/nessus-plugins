#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(129493);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/02");

  script_cve_id("CVE-2017-16544", "CVE-2019-5531");
  script_bugtraq_id(93287);
  script_xref(name:"VMSA", value:"2019-0013");
  script_xref(name:"IAVA", value:"2019-A-0344");

  script_name(english:"ESXi 6.0 / 6.5 / 6.7 Multiple Vulnerabilities (VMSA-2019-0013)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security patch and is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 6.0, 6.5 or 6.7 and is affected the following vulnerabilities:

  - A remote code execution vulnerability caused by
    a failure to sanitize filenames in the tab autocomplete
    feature of BusyBox. This allows an attacker to execute
    arbitrary code, write arbitrary files, or conduct other
    attacks. (CVE-2017-16544)

  - An information disclosure vulnerability caused by
    insufficient session expiration. This allows an
    attacker with physical access or the ability to mimic
    a websocket connection to a user's browser to control
    a VM console after the user's session has expired or
    they have logged out. (CVE-2019-5531)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0013.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16544");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release", "Host/VMware/vsphere", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array(
  '6.0', '14513180',
  '6.5', '13873656',
  '6.7', '12986307'
);

rel = get_kb_item_or_exit('Host/VMware/release');
if ('ESXi' >!< rel) audit(AUDIT_OS_NOT, 'ESXi');

ver = get_kb_item_or_exit('Host/VMware/version');
port = get_kb_item_or_exit('Host/VMware/vsphere');

match = pregmatch(pattern:'^ESXi? ([0-9]+\\.[0-9]+).*$', string:ver);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.0 / 6.5 / 6.7');
ver = match[1];

if (ver !~ '^6\\.(0|5|7)$') audit(AUDIT_OS_NOT, 'ESXi 6.0 / 6.5 / 6.7');

fixed_build = int(fixes[ver]);

if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = pregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.0 / 6.5 / 6.7');

build = int(match[1]);

if (build >= fixed_build) audit(AUDIT_INST_VER_NOT_VULN, 'VMware ESXi', ver + ' build ' + build);

report = '\n  ESXi version    : ' + ver +
         '\n  Installed build : ' + build +
         '\n  Fixed build     : ' + fixed_build +
         '\n';

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
