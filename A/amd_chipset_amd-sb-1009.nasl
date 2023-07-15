#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153836);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/08");

  script_cve_id("CVE-2021-26333");
  script_xref(name:"IAVA", value:"2021-A-0443");

  script_name(english:"AMD Platform Security Processor (PSP) Chipset Driver Information Disclosure (AMD-SB-1009)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a chipset driver that is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the AMD Platform Security Processor (PSP) chipset driver found on the remote host is prior to 5.17.0.0.
It is, therefore, affected by an information disclosure vulnerability. The discretionary access control list (DACL) may
allow low privileged users to open a handle and send requests to the driver resulting in a potential data leak from
uninitialized physical pages.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.amd.com/en/corporate/product-security/bulletin/amd-sb-1009");
  script_set_attribute(attribute:"solution", value:
"Update to AMD PSP driver 5.17.0.0 through Windows Update or by updating to AMD Chipset Driver 3.08.17.735.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26333");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:amd:platform_security_processor_chipset_driver");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app = 'AMD Platform Security Processor (PSP) Chipset Driver';

var systemroot = hotfix_get_systemroot();
if (isnull(systemroot))
  audit(AUDIT_PATH_NOT_DETERMINED, 'SystemRoot');

var driver_path = hotfix_append_path(path:systemroot, value:'\\system32\\drivers\\amdpsp.sys');

hotfix_check_fversion_init();

if (!hotfix_file_exists(path:driver_path))
{
  hotfix_check_fversion_end();
  audit(AUDIT_NOT_INST, app);
}

var ver = hotfix_get_fversion(path:driver_path);
hotfix_handle_error(
  error_code:ver['error'],
  file:driver_path,
  appname:app,
  exit_on_fail:TRUE
);

hotfix_check_fversion_end();

ver = join(sep:'.', ver['value']);

var fixed_ver = '5.17.0.0';
if (ver_compare(ver:ver, fix:fixed_ver, strict:FALSE) < 0)
{
  report = '\n  Path              : ' + driver_path +
           '\n  Installed Version : ' + ver +
           '\n  Fixed version     : ' + fixed_ver;
  
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);
