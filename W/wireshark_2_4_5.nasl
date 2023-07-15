#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107093);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2018-7320",
    "CVE-2018-7321",
    "CVE-2018-7322",
    "CVE-2018-7323",
    "CVE-2018-7324",
    "CVE-2018-7325",
    "CVE-2018-7326",
    "CVE-2018-7327",
    "CVE-2018-7328",
    "CVE-2018-7329",
    "CVE-2018-7330",
    "CVE-2018-7331",
    "CVE-2018-7332",
    "CVE-2018-7333",
    "CVE-2018-7334",
    "CVE-2018-7335",
    "CVE-2018-7336",
    "CVE-2018-7337"
  );
  script_bugtraq_id(
    103158,
    103160,
    103162,
    103164,
    103165,
    103166
  );

  script_name(english:"Wireshark 2.2.x < 2.2.13 / 2.4.x < 2.4.5 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is 
2.2.x prior to 2.2.13 or 2.4.x prior to 2.4.5. It is, therefore, 
affected by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-05.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-06.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-07.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-08.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-09.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-10.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-11.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-13.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.2.13 / 2.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7337");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"Wireshark", win_local:TRUE);

constraints = [
  { "min_version" : "2.2.0", "fixed_version" : "2.2.13" },
  { "min_version" : "2.4.0", "fixed_version" : "2.4.5" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
