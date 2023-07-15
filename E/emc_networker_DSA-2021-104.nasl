#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150504);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id("CVE-2021-21558", "CVE-2021-21559");
  script_xref(name:"IAVA", value:"2021-A-0265-S");

  script_name(english:"Dell EMC NetWorker Multiple Vulnerabilities (DSA-2021-104)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell EMC NetWorker installed on the remote Windows host is prior to 19.4.0.2. It is, therefore,
affected by multiple vulnerabilities:

  - Dell EMC NetWorker 18.x, 19.1.x, 19.2.x, 19.3.x, 19.4 and 19.4.0.1, contains an Information Disclosure
    vulnerability. A local administrator of the gstd system may potentially exploit this vulnerability to
    read LDAP credentials from local logs and use the stolen credentials to make changes to the network
    domain. (CVE-2021-21558)

  - Dell EMC NetWorker versions 18.x, 19.1.x, 19.2.x, 19.3.x, 19.4, and 19.4.0.1 contain an Improper
    Certificate Validation vulnerability in the client (NetWorker Management Console) components which
    uses SSL encrypted connection in order to communicate with the application server.  An unauthenticated
    attacker in the same network collision domain as the NetWorker Management Console client could potentially
    exploit this vulnerability to perform man-in-the-middle attacks to intercept and tamper the traffic
    between the client and the application server. (CVE-2021-21559)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000186638/dsa-2021-104-dell-emc-networker-security-update-for-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0ffbf2a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell EMC NetWorker 19.4.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21559");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:emc_networker");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'EMC NetWorker', win_local:TRUE);

if (app_info['Management Console Installed'] == 'false')
  audit(AUDIT_INST_PATH_NOT_VULN, 'EMC NetWorker', app_info.version, app_info.path);

var constraints = [
  { 'min_version' : '18.0', 'max_version' : '19.4.0.1', 'fixed_version' : '19.4.0.2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);

