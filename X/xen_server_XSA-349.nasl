##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145546);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-29568");
  script_xref(name:"IAVB", value:"2020-B-0077-S");

  script_name(english:"Xen OOM DoS (XSA-349)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by a denial
of service vulnerability due to an issue with the watch event queue. A malicious guest can exploit this, by abusing the
unbounded queue, to cause an out-of-memory error in the backend, which can result in a DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-349.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29568");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app = 'Xen Hypervisor';

app_info = vcf::xen_hypervisor::get_app_info(app:app);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# All versions through 4.14.x

fixes['4.10']['fixed_ver']           = '4.10.99';
fixes['4.10']['fixed_ver_display']   = 'See vendor advisory';
fixes['4.10']['affected_ver_regex']  = "^4\.10\.";

fixes['4.11']['fixed_ver']           = '4.11.99';
fixes['4.11']['fixed_ver_display']   = 'See vendor advisory';
fixes['4.11']['affected_ver_regex']  = "^4\.11\.";

fixes['4.12']['fixed_ver']           = '4.12.99';
fixes['4.12']['fixed_ver_display']   = 'See vendor advisory';
fixes['4.12']['affected_ver_regex']  = "^4\.12\.";

fixes['4.13']['fixed_ver']           = '4.13.99';
fixes['4.13']['fixed_ver_display']   = 'See vendor advisory';
fixes['4.13']['affected_ver_regex']  = "^4\.13\.";

fixes['4.14']['fixed_ver']           = '4.14.99';
fixes['4.14']['fixed_ver_display']   = 'See vendor advisory';
fixes['4.14']['affected_ver_regex']  = "^4\.14\.";

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);
