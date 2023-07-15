##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146433);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/12");

  script_cve_id(
    "CVE-2019-12462",
    "CVE-2019-12949",
    "CVE-2019-16914",
    "CVE-2019-16915"
  );

  script_name(english:"pfSense < 2.4.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense install is to 2.4.5. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - In pfSense 2.4.4-p2 and 2.4.4-p3, if it is possible to trick an authenticated administrator into clicking
    on a button on a phishing page, an attacker can leverage XSS to upload arbitrary executable code, via
    diag_command.php and rrd_fetch_json.php (timePeriod parameter), to a server. Then, the remote attacker can
    run any command with root privileges on that server. (CVE-2019-12949)

  - An XSS issue was discovered in pfSense through 2.4.4-p3. In services_captiveportal_mac.php, the username
    and delmac parameters are displayed without sanitization. (CVE-2019-16914)

  - An issue was discovered in pfSense through 2.4.4-p3. widgets/widgets/picture.widget.php uses the widgetkey
    parameter directly without sanitization (e.g., a basename call) for a pathname to file_get_contents or
    file_put_contents. (CVE-2019-16915)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.netgate.com/pfsense/en/latest/releases/2-4-5.html");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-20_01.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1016ba4d");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-20_02.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?585c5ae8");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-20_03.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82bd096d");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-20_04.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f44e91d");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-20_05.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7044ef9");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-20_06.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2d565cd");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-20_07.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6be62679");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.4.5 or later, or apply patches as noted in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netgate:pfsense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pfsense_detect.nbin");
  script_require_keys("Host/pfSense");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

if (!get_kb_item('Host/pfSense')) audit(AUDIT_HOST_NOT, 'pfSense');

app_info = vcf::pfsense::get_app_info();
constraints = [
  {'fixed_version':'2.4.5'}
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE}
);
