#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136746);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2020-3956");
  script_xref(name:"VMSA", value:"2020-0010");
  script_xref(name:"IAVA", value:"2020-A-0223");

  script_name(english:"VMware Cloud Director 9.1.x < 9.1.0.4 / 9.5.x < 9.5.0.6 / 9.7.x < 9.7.0.5 / 10.0.x < 10.0.0.2 Code Injection (VMSA-2020-0010)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCloud Director installed on the remote host is 9.1.x prior to 9.1.0.4, 9.5.x prior to 9.5.0.6,
9.7.x prior to 9.7.0.5, or 10.0.x prior to 10.0.0.2. It is, therefore, affected by a code injection vulnerability due to
a failure to properly handle input. A remote, authenticated actor can exploit this, by sending malicious traffic to
VMWare Cloud Director, in order to execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0010.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCloud Director version 9.1.0.4 / 9.5.0.6 / 9.7.0.5 / 10.0.0.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3956");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcloud_director");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vcloud_director_installed.nbin");
  script_require_keys("Host/VMware vCloud Director/Version", "Host/VMware vCloud Director/Build");

  exit(0);
}

version = get_kb_item_or_exit("Host/VMware vCloud Director/Version");
build = get_kb_item_or_exit("Host/VMware vCloud Director/Build");

fixed_ver = '';
fixed_build = '';

if (version =~ "^9\.1\.")
{
  fixed_ver = '9.1.0.4';
  fixed_build = '16217117';
}
else if (version =~ "^9\.5\.")
{
  fixed_ver = '9.5.0.6';
  fixed_build = '16181458';
}
else if (version =~ "^9\.7\.")
{
  fixed_ver = '9.7.0.5';
  fixed_build = '16081827';
}
else if (version =~ "^10\.0\.")
{
  fixed_ver = '10.0.0.2';
  fixed_build = '16081830';
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware Cloud Director', version + ' Build ' + build);

if (
  (ver_compare(ver:version, fix:fixed_ver, strict:FALSE) < 0) &&
  (build < fixed_build)
)
{
  report = '\n  Installed version : ' + version + ' Build ' + build +
           '\n  Fixed version     : ' + fixed_ver + ' Build ' + fixed_build +
           '\n';
  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware Cloud Director', version + ' Build ' + build);

