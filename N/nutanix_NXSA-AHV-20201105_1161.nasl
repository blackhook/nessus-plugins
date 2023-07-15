#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164553);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id("CVE-2020-8625");

  script_name(english:"Nutanix AHV : (NXSA-AHV-20201105.1161)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20201105.1161. It is, therefore, affected by a vulnerability
as referenced in the NXSA-AHV-20201105.1161 advisory.

  - BIND servers are vulnerable if they are running an affected version and are configured to use GSS-TSIG
    features. In a configuration which uses BIND's default settings the vulnerable code path is not exposed,
    but a server can be rendered vulnerable by explicitly setting valid values for the tkey-gssapi-keytab or
    tkey-gssapi-credentialconfiguration options. Although the default configuration is not vulnerable, GSS-
    TSIG is frequently used in networks where BIND is integrated with Samba, as well as in mixed-server
    environments that combine BIND servers with Active Directory domain controllers. The most likely outcome
    of a successful exploitation of the vulnerability is a crash of the named process. However, remote code
    execution, while unproven, is theoretically possible. Affects: BIND 9.5.0 -> 9.11.27, 9.12.0 -> 9.16.11,
    and versions BIND 9.11.3-S1 -> 9.11.27-S1 and 9.16.8-S1 -> 9.16.11-S1 of BIND Supported Preview Edition.
    Also release versions 9.17.0 -> 9.17.1 of the BIND 9.17 development branch (CVE-2020-8625)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20201105.1161
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c1c4fb0");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8625");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:ahv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/Node/Version", "Host/Nutanix/Data/Node/Type");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info(node:TRUE);

var constraints = [
  { 'fixed_version' : '20201105.1161', 'product' : 'AHV', 'fixed_display' : 'Upgrade the AHV install to 20201105.1161 or higher.' }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
