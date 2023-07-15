#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118975);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-15980");
  script_bugtraq_id(105905);

  script_name(english:"Adobe Photoshop CC 19.x < 19.1.7 Information Disclosure Vulnerability (APSB18-43) (macOS)");
  script_summary(english:"Checks the Photoshop version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop CC installed on the remote macOS or
Mac OS X host is 19.x prior to 19.1.7 (2018.1.7). It is, therefore,
affected by an out-of-bounds read allowing the disclosure of sensitive
information.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb18-43.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CC 19.1.7 (2018.1.7), 20.0 (2019.0), or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_photoshop_installed.nasl");
  script_require_keys("Host/MacOSX/Version", "installed_sw/Adobe Photoshop");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("Host/MacOSX/Version");

app_info = vcf::get_app_info(app:"Adobe Photoshop");

if ("CC" >!< app_info.name) vcf::vcf_exit(0, "Only Adobe Photoshop CC is affected.");
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "19", "fixed_version" : "19.1.7" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
