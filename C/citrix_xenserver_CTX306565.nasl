##
# (C) Tenable Network Security, Inc
##

include('compat.inc');

if (description)
{
  script_id(148674);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2020-35498", "CVE-2021-28038", "CVE-2021-28688");

  script_name(english:"Citrix Hypervisor <= 8.2 LTSR DoS (CTX306565)");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Hypervisor (formerly Citrix XenServer) running on the remote host is missing a security hotfix. 
It is, therefore, affected by denial of service vulnerabilities. 

 - A local attacker with the ability to execute privileged mode code in a guest machine can perform a denial of service
   attack against the host causing the host to crash or become unresponsive. Please refer to the vendor advisory for
   mitigating factors. (CVE-2021-28038)
   
 - A vulnerability was found in openvswitch. A limitation in the implementation of userspace packet parsing can allow a
   malicious user to send a specially crafted packet causing the resulting megaflow in the kernel to be too wide, 
   potentially causing a denial of service. The highest threat from this vulnerability is to system availability.
   (CVE-2020-35498)
 
 - A local attacker with the ability to execute privileged mode code in a guest machine can perform a denial of service
   attack against the host causing the host to crash or become unresponsive. Please refer to the vendor advisory for
   mitigating factors. (CVE-2021-28688)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX306565");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35498");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Host/XenServer/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::xenserver::get_app_info();

constraints = [
  { 'equal' : '7.0',    'patches' :           # XenServer 7.0
                          ['XS70E092'] },     # CTX306482
  { 'equal' : '7.1.2',  'patches' :           # XenServer 7.1 LTSR CU2
                          ['XS71ECU2058'] },  # CTX306480
  { 'equal' : '8.2',    'patches' :           # Hypervisor 8.2.
                          ['XS82E024', 'XS82E022'] }      # CTX306481, CTX306423
];

vcf::xenserver::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
