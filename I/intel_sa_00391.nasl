##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143152);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id(
    "CVE-2020-8705",
    "CVE-2020-8744",
    "CVE-2020-8745",
    "CVE-2020-8746",
    "CVE-2020-8747",
    "CVE-2020-8749",
    "CVE-2020-8751",
    "CVE-2020-8752",
    "CVE-2020-8753",
    "CVE-2020-8754",
    "CVE-2020-8755",
    "CVE-2020-8756",
    "CVE-2020-8757",
    "CVE-2020-8760",
    "CVE-2020-8761",
    "CVE-2020-12297",
    "CVE-2020-12303",
    "CVE-2020-12354",
    "CVE-2020-12356"
  );
  script_xref(name:"IAVA", value:"2020-A-0534");

  script_name(english:"Intel Active Management Technology (AMT) Multiple Vulnerabilities (INTEL-SA-00391) (remote check)");

  script_set_attribute(attribute:"synopsis", value:
"The management engine on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Intel Management Engine on the remote host has Active Management Technology (AMT) enabled, and, according to its
self-reported, is a version containing multiple vulnerabilities, including the following:

  - Out-of-bounds write in IPv6 subsystem for Intel(R) AMT, Intel(R) ISM versions before 11.8.80, 11.12.80,
    11.22.80, 12.0.70, 14.0.45 may allow an unauthenticated user to potentially enable escalation of
    privileges via network access. (CVE-2020-8752)

  - Out-of-bounds read in subsystem for Intel(R) AMT versions before 11.8.80, 11.12.80, 11.22.80, 12.0.70 and
    14.0.45 may allow an unauthenticated user to potentially enable information disclosure and/or denial of
    service via network access. (CVE-2020-8747)

  - Out-of-bounds read in subsystem for Intel(R) AMT versions before 11.8.80, 11.12.80, 11.22.80, 12.0.70 and
    14.0.45 may allow an unauthenticated user to potentially enable escalation of privilege via adjacent
    access. (CVE-2020-8749)


Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00391.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2fdd021");
  script_set_attribute(attribute:"solution", value:
"Contact your system OEM for updated firmware per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:active_management_technology");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:intel:active_management_technology_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intel_amt_remote_detect.nbin");
  script_require_keys("installed_sw/Intel Active Management Technology");
  script_require_ports("Services/www", 16992, 16993, 16994, 16995, 623, 664);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_kb_item_or_exit('installed_sw/Intel Active Management Technology');

port = get_http_port(default:16992);

app = 'Intel Active Management Technology';
app_info = vcf::get_app_info(app:app, port:port);

constraints = [
  { 'min_version' : '11.8',  'fixed_version' : '11.8.80' },
  { 'min_version' : '11.12', 'fixed_version' : '11.12.80' },
  { 'min_version' : '11.22', 'fixed_version' : '11.22.80' },
  { 'min_version' : '12.0',  'fixed_version' : '12.0.70' },
  { 'min_version' : '13.0',  'fixed_version' : '13.0.40' },
  { 'min_version' : '13.30', 'fixed_version' : '13.30.10' },
  { 'min_version' : '14.0',  'fixed_version' : '14.0.45' },
  { 'min_version' : '14.5',  'fixed_version' : '14.5.25' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
