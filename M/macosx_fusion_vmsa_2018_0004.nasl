#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105781);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-4949", "CVE-2017-4950", "CVE-2017-5715");
  script_bugtraq_id(102376, 102489, 102490);
  script_xref(name:"VMSA", value:"2018-0004");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"VMSA", value:"2018-0005");

  script_name(english:"VMware Fusion 8.x < 8.5.10 / 10.x < 10.1.1 Multiple Vulnerabilities (VMSA-2018-0004) (VMSA-2018-0005) (Spectre) (macOS)");
  script_summary(english:"Checks the VMware Fusion version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote macOS or Mac OS X
host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the remote macOS or 
Mac OS X host is 8.x prior to 8.5.10 or 10.x prior to 10.1.1. It is,
therefore, missing security updates that add hypervisor-assisted
guest remediation for a speculative execution vulnerability
(CVE-2017-5715). These updates will allow guest operating
systems to use hardware support for branch target mitigation and
will require guest OS security updates as detailed in VMware
Knowledge Base article 52085.
It is also affected by use-after-free and integer-overflow vulnerabilities.

Note that hypervisor-specific remediation's for this vulnerability
were released as part of VMSA-2018-0002.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/us/security/advisories/VMSA-2018-0004.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0005.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/52085");
  script_set_attribute(attribute:"see_also", value:"https://spectreattack.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Fusion version 8.5.10 / 10.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4950");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Fusion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

install = get_single_install(app_name:"VMware Fusion", exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

fix = '';
if (version =~ "^8\.") fix = '8.5.10';
else if(version =~ "^10\.") fix = '10.1.1';

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Fusion", version, path);
