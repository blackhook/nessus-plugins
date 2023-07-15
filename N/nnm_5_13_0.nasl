#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(147729);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-11022", "CVE-2020-11023");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Nessus Network Monitor < 5.13.0 Multiple Vulnerabilities (TNS-2021-02)");

  script_set_attribute(attribute:"synopsis", value:
"A vulnerability scanner installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Nessus Network Monitor (NNM) installed
on the remote host is prior to 5.13.0. It is, therefore, affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-02");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/products/nessus/nessus-network-monitor");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus Network Monitor version 5.13.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11022");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nnm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nnm_installed_win.nbin", "nnm_installed_nix.nbin");
  script_require_keys("installed_sw/Tenable NNM", "Host/nnm_installed");

  exit(0);
}

include('vcf.inc');

app_name = 'Tenable NNM';

app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '5.13.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

