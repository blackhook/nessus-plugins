#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106502);
  script_version("1.12");
  script_cvs_date("Date: 2018/12/07 17:08:17");

  script_cve_id(
    "CVE-2013-7456",
    "CVE-2016-5093",
    "CVE-2016-5094",
    "CVE-2016-5096"
  );
  script_bugtraq_id(
    90857,
    90859,
    90861,
    90946
  );

  script_name(english:"pfSense < 2.3.1-p5 Multiple Vulnerabilities (SA-16_07 / SA-16_08)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is prior to 2.3.1-p5. It is, therefore, affected by multiple
vulnerabilities as stated in the referenced vendor advisories.");
  script_set_attribute(attribute:"see_also", value:"https://doc.pfsense.org/index.php/2.3.1_New_Features_and_Changes");
  # https://www.pfsense.org/security/advisories/pfSense-SA-16_07.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9b195dd");
  # https://www.pfsense.org/security/advisories/pfSense-SA-16_08.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36080faa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.3.1-p5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5093");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pfsense_detect.nbin");
  script_require_keys("Host/pfSense");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

if (!get_kb_item("Host/pfSense")) audit(AUDIT_HOST_NOT, "pfSense");

app_info = vcf::pfsense::get_app_info();
constraints = [
  { "fixed_version" : "2.3.1-p5" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
