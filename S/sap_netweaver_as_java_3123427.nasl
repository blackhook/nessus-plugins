#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157847);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2022-22532", "CVE-2022-22533");
  script_xref(name:"IAVA", value:"2022-A-0063");
  script_xref(name:"CEA-ID", value:"CEA-2022-0006");

  script_name(english:"SAP NetWeaver AS Java Multiple Vulnerabilities (ICMAD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"SAP NetWeaver Application Server Java is vulnerable to HTTP request smuggling.

  - An unauthenticated attacker could submit a crafted HTTP server request which triggers improper shared memory 
    buffer handling. This could allow the malicious payload to be executed and hence execute functions that could 
    be impersonating the victim or even steal the victim's logon session. (CVE-2022-22532)

  - Due to improper error handling, an attacker could submit multiple HTTP server requests resulting in errors, 
    such that it consumes the memory buffer. This could result in system shutdown rendering the system unavailable.
    (CVE-2022-22533)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://blogs.sap.com/2022/02/08/sap-partners-with-onapsis-to-identify-and-patch-cybersecurity-vulnerabilities/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0c19cc7");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3123427");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22532");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('vcf_extras_sap.inc');

var app_info = vcf::sap_netweaver_as::get_app_info(kernel:TRUE);

# it only affects AS Java, but we have to check the kernel version
if (empty_or_null(app_info['AS Java Version']))
  vcf::audit(app_info);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var fix = 'See vendor advisory';

# Kernel constraints
var constraints = [
        {'equal' : '7.22', 'fixed_display' : fix },
        {'equal' : '7.49', 'fixed_display' : fix },
        {'equal' : '7.53', 'fixed_display' : fix }
    ];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  kernel:TRUE
);
