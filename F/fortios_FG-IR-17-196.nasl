#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103873);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-13077",
    "CVE-2017-13078",
    "CVE-2017-13079",
    "CVE-2017-13080",
    "CVE-2017-13081"
  );
  script_bugtraq_id(99549, 100516, 101274);
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"Fortinet FortiGate < 5.2 / 5.2.x <= 5.2.11 / 5.4.x <= 5.4.5 / 5.6.x <= 5.6.2 Multiple Vulnerabilities (FG-IR-17-196) (KRACK)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running FortiOS prior to 5.2, 5.2.x prior to
or equal to 5.2.11, 5.4.x prior to or equal 5.4.5, or 5.6.x prior to
or equal to 5.6.2. It is, therefore, affected by multiple
vulnerabilities discovered in the WPA2 handshake protocol.

Note these issues affect only WiFi model devices in
'Wifi Client' mode.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-17-196");
  script_set_attribute(attribute:"see_also", value:"https://www.krackattacks.com/");
  script_set_attribute(attribute:"solution", value:
"Contact vendor for guidance and patches.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13077");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("vcf.inc");

app_name = "FortiOS";

model = get_kb_item_or_exit("Host/Fortigate/model");

# Make sure device is FortiWiFi.
if (!preg(string:model, pattern:"fortiwifi", icase:TRUE)) audit(AUDIT_HOST_NOT, "a FortiGate WiFi model");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:app_name, kb_ver:"Host/Fortigate/version");

constraints = [
  # < 5.2
  { "min_version" : "0.0.0", "max_version" : "5.2.0",  "fixed_display" : "See Solution." },
  # 5.2 x <= 5.2.11
  { "min_version" : "5.2.0", "max_version" : "5.2.11", "fixed_display" : "See Solution." },
  # 5.4.x <= 5.4.5
  { "min_version" : "5.4.0", "max_version" : "5.4.5",  "fixed_display" : "See Solution." },
  # 5.6.x <= 5.6.2
  { "min_version" : "5.6.0", "max_version" : "5.6.2",  "fixed_display" : "See Solution." }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
