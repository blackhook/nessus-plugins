#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140772);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-3986",
    "CVE-2020-3987",
    "CVE-2020-3988",
    "CVE-2020-3989",
    "CVE-2020-3990"
  );
  script_xref(name:"VMSA", value:"2020-0020");
  script_xref(name:"IAVA", value:"2020-A-0437");

  script_name(english:"VMware Horizon View Client < 5.4.4 Multiple Vulnerabilities (VMSA-2020-0020)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon Client for Windows installed on the remote host is less than 5.4.4. It is, therefore,
affected by the following vulnerabilities:

  - Multiple out-of-bounds read vulnerabilities in Cortado ThinPrint components JPEG2000 parser, EMR
    STRETCHDIBITS parser, and EMF Parser. A malicious actor with normal access to a virtual machine can
    exploit these issues to create a partial denial-of-service condition or to leak memory from TPView process
    running on the system where Horizon Client is installed. (CVE-2020-3986, CVE-2020-3987, CVE-2020-3988)

  - A denial of service (DoS) vulnerability due to an out-of-bounds write issue in a Cortado ThinPrint
    component. A malicious actor with normal access to a virtual machine can exploit this issue to create a
    partial denial-of-service condition on the system where Horizon Client is installed. Exploitation is only
    possible if virtual printing has been enabled. This feature is enabled by default on Horizon Client.
    (CVE-2020-3989)

  - An information disclosure vulnerability due to an integer overflow issue in Cortado ThinPrint component. A
    malicious actor with normal access to a virtual machine can exploit this issue to leak memory from TPView
    process running on the system where Horizon Client is installed. Exploitation is only possible if virtual
    printing has been enabled. This feature is enabled by default on Horizon Client. (CVE-2020-3990)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0020.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMWare Horizon View Client 5.4.4 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3988");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-3990");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view_client");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_horizon_view_client_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Horizon View Client");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'VMware Horizon View Client', win_local:TRUE);

constraints = [{ 'fixed_version' : '5.4.4' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
