#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102132);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2017-3132", "CVE-2017-3133");
  script_bugtraq_id(100009);
  script_xref(name:"EDB-ID", value:"42388");

  script_name(english:"Fortinet FortiOS 5.2.x < 5.2.12 / 5.4.x < 5.4.6 / 5.6.x < 5.6.1 Multiple Vulnerabilities (FG-IR-17-104)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiOS running on the remote device is 5.2.x
prior to 5.2.12, 5.4.x prior to 5.4.6, or 5.6.x prior to 5.6.1. It is,
therefore, affected by multiple vulnerabilities including multiple
cross-site scripting (XSS) vulnerabilities and a flaw in the support
of Server Message Block (SMB)v1 protocol.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-17-103");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-17-104");
  # https://docs.fortinet.com/uploaded/files/4010/fortios-v5.2.12-release-notes.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bcbeff6f");
  # https://docs.fortinet.com/uploaded/files/4002/fortios-v5.4.6-release-notes.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2afb3adf");
  # https://docs.fortinet.com/uploaded/files/3879/fortios-v5.6.1-release-notes.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?299b39c4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 5.2.12 / 5.4.6 / 5.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3133");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

app_info = vcf::get_app_info(app:"FortiOS", kb_ver:"Host/Fortigate/version", webapp:true);

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  { "min_version" : "5.2.0", "fixed_version" : "5.2.12" },
  { "min_version" : "5.4.0", "fixed_version" : "5.4.6" },
  { "min_version" : "5.6.0", "fixed_version" : "5.6.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:true});
