#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(106495);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2014-8176",
    "CVE-2015-1788",
    "CVE-2015-1789",
    "CVE-2015-1790",
    "CVE-2015-1791",
    "CVE-2015-1792",
    "CVE-2015-2325",
    "CVE-2015-2326",
    "CVE-2015-3414",
    "CVE-2015-3415",
    "CVE-2015-3416",
    "CVE-2015-4000",
    "CVE-2015-4029",
    "CVE-2015-4171",
    "CVE-2015-4598",
    "CVE-2015-4642",
    "CVE-2015-4643",
    "CVE-2015-4644",
    "CVE-2015-6508",
    "CVE-2015-6509",
    "CVE-2015-6510",
    "CVE-2015-6511"
  );
  script_bugtraq_id(
    74228,
    75174,
    75175,
    75244,
    75290,
    75291,
    75292
  );
  script_xref(name:"FreeBSD", value:"SA-15:10.openssl");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"pfSense < 2.2.3 Multiple Vulnerabilities (SA-15_07) (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is prior to 2.2.3. It is, therefore, affected by multiple
vulnerabilities as stated in the referenced vendor advisories.");
  script_set_attribute(attribute:"see_also", value:"https://doc.pfsense.org/index.php/2.2.3_New_Features_and_Changes");
  # https://www.pfsense.org/security/advisories/pfSense-SA-15_06.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61bea99f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4642");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pfsense_detect.nbin");
  script_require_keys("Host/pfSense");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

if (!get_kb_item("Host/pfSense")) audit(AUDIT_HOST_NOT, "pfSense");

app_info = vcf::pfsense::get_app_info();
constraints = [
  { "fixed_version" : "2.2.3" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
