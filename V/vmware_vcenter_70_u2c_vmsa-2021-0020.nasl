#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153545);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id(
    "CVE-2021-21991",
    "CVE-2021-21992",
    "CVE-2021-21993",
    "CVE-2021-22005",
    "CVE-2021-22006",
    "CVE-2021-22007",
    "CVE-2021-22008",
    "CVE-2021-22009",
    "CVE-2021-22010",
    "CVE-2021-22014",
    "CVE-2021-22015",
    "CVE-2021-22019",
    "CVE-2021-22020"
  );
  script_xref(name:"IAVA", value:"2021-A-0434-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0045");

  script_name(english:"VMware vCenter Server < 7.0 U2c Multiple Vulnerabilities (VMSA-2021-0020)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is 7.0 prior to 7.0 U2c. It is, therefore, affected
 by multiple vulnerabilities:

    - An arbitrary file upload vulnerability exists in the analytics service of vSphere Server. An 
      unauthenticated, remote attacker can exploit this to upload arbitrary files on the remote host 
      and execute code using a specially crafted file. (CVE-2021-22005)

    - A privilege escalation vulnerability exists in vCenter Server due to the way it handles session tokens. 
      An authenticated, local attacker can exploit this to gain unauthorized access to the system. 
      (CVE-2021-21991, CVE-2021-22015)

    - A reverse proxy bypass vulnerability exists in vCenter Server due to the way the endpoints handle the URI. 
      An unauthenticated, remote attacker can exploit this to gain unauthorized access to restricted endpoints.
      (CVE-2021-22006) 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number. Nessus has also not tested for the presence of a workaround.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0020.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 7.0 U2c or later or apply the workaround mentioned in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22014");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-22005");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMware vCenter Server Analytics (CEIP) Service File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

var fixes = make_array(
  '7.0', '18356314'  # 7.0 U2c
);

var port = get_kb_item_or_exit('Host/VMware/vCenter');
var version = get_kb_item_or_exit('Host/VMware/version');
var release = get_kb_item_or_exit('Host/VMware/release');

# Extract and verify the build number
var build = ereg_replace(pattern:"^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$", string:release, replace:"\1");
if (build !~ "^[0-9]+$") audit(AUDIT_UNKNOWN_BUILD, 'VMware vCenter 7.0');

var match = pregmatch(pattern:"^VMware vCenter ([0-9]+\.[0-9]+).*$", string:version);
if (isnull(match)) audit(AUDIT_OS_NOT, 'VMware vCenter 7.0');

var ver = match[1];
if (ver !~ "^7\.0$") audit(AUDIT_OS_NOT, 'VMware vCenter 7.0');

var fixed_build = int(fixes[ver]);
if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

release = release - 'VMware vCenter Server ';
if (build >= fixed_build)
  audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

var report =  '\n  VMware vCenter version    : ' + ver +
              '\n  Installed build           : ' + build +
              '\n  Fixed build               : ' + fixed_build +
              '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
