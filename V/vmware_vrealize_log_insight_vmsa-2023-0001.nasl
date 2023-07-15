#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, inc.
##

include('compat.inc');

if (description)
{
  script_id(170661);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/02");

  script_cve_id(
    "CVE-2022-31704",
    "CVE-2022-31706",
    "CVE-2022-31710",
    "CVE-2022-31711"
  );
  script_xref(name:"IAVA", value:"2023-A-0057-S");

  script_name(english:"VMware vRealize Log Insight 8.x < 8.10.2 Mutliple Vulnerabilities (VMSA-2023-0001)");

  script_set_attribute(attribute:"synopsis", value:
"A log management application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware vRealize Log Insight application running on the remote host is 8.x prior to 8.10.2. It is,
therefore, affected by multiple vulnerabilities, including:

    - An unspecified directory traversal vulnerability. (CVE-2022-31706)

    - An unspecified broken access control vulnerability. (CVE-2022-31704)

    - An unspecified deserialization vulnerability. (CVE-2022-31710)

    - An unspecified information disclosure vulnerability. (CVE-2022-31711)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0001.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Log Insight version 8.10.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31706");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_log_insight");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vrealize_log_insight_webui_detect.nbin", "vmware_vrealize_log_insight_nix.nbin");
  script_require_keys("installed_sw/VMware vRealize Log Insight");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'VMware vRealize Log Insight');

var constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.10.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
