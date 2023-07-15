#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134876);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/26");

  script_cve_id("CVE-2016-7463");
  script_bugtraq_id(94998);
  script_xref(name:"VMSA", value:"2016-0023");

  script_name(english:"VMware ESXi 5.5 / 6.0 XSS (VMSA-2016-0023) (remote check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security patch and is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.5 or 6.0, and is missing a security patch. It is, therefore, vulnerable to a
cross-site scripting (XSS) vulnerability. The vulnerability exists due to improper validation of user-supplied input
before returning it to users. An authenticated, remote attacker can exploit this, by importing a specially crafted VM,
to inject arbitrary web script or HTML.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7463");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

rel = get_kb_item_or_exit("Host/VMware/release");
if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");

ver = get_kb_item_or_exit("Host/VMware/version");

match = pregmatch(pattern:"^ESXi? ([0-9]+\.[0-9]+).*$", string:ver);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "5.5 / 6.0");
ver = match[1];

if (ver != '5.5' && ver != '6.0')
  audit(AUDIT_OS_NOT, "ESXi 5.5 / 6.0");

# Patches for this do not patch esx-base, therefore might not be detected remotely.
if(report_paranoia < 2)
  audit(AUDIT_PARANOID);

report =  '\n ESXi version ' + ver + ' is affected by this vulnerability.\n' +
          '\n This particular patch cannot be detected remotely.\n';

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report, xss:TRUE);
