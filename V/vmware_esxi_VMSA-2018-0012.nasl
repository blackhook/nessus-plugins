#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134877);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2018-3639");
  script_bugtraq_id(104232);
  script_xref(name:"VMSA", value:"2018-0012");

  script_name(english:"VMware ESXi 5.5 / 6.0 / 6.5 / 6.7 Information Disclosure (VMSA-2018-0012) (Spectre) (remote check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security patch and is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.5, 6.0, 6.5, or 6.7 and is missing a security patch. It is, therefore,
vulnerable to an information disclosure vulnerability. The vulnerability exists in the speculative execution control
mechanism. An unauthenticated, local attacker can exploit this, via side-channel analysis, to disclose potentially
sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0012.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3639");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release", "Host/VMware/vsphere");

  exit(0);
}

rel = get_kb_item_or_exit("Host/VMware/release");
if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");

ver = get_kb_item_or_exit("Host/VMware/version");
port = get_kb_item_or_exit("Host/VMware/vsphere");

match = pregmatch(pattern:"^ESXi? ([0-9]+\.[0-9]+).*$", string:ver);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "5.5 / 6.0 / 6.5 / 6.7");
ver = match[1];

if (ver != '5.5' && ver != '6.0' && ver != '6.5' && ver != '6.7')
  audit(AUDIT_OS_NOT, "ESXi 5.5 / 6.0 / 6.5 / 6.7");

# Can't check for microcode patch remotely, as it doesn't modify esx-base build version
if(report_paranoia < 2)
  audit(AUDIT_PARANOID);

report =  '\n  ESXi version ' + ver + ' is affected by this vulnerability.\n' +
          '\n  This particular patch cannot be detected remotely.\n';

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
