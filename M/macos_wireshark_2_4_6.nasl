#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108884);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2017-9616",
    "CVE-2018-9256",
    "CVE-2018-9257",
    "CVE-2018-9258",
    "CVE-2018-9259",
    "CVE-2018-9260",
    "CVE-2018-9261",
    "CVE-2018-9262",
    "CVE-2018-9263",
    "CVE-2018-9264",
    "CVE-2018-9265",
    "CVE-2018-9266",
    "CVE-2018-9267",
    "CVE-2018-9268",
    "CVE-2018-9269",
    "CVE-2018-9270",
    "CVE-2018-9271",
    "CVE-2018-9272",
    "CVE-2018-9273",
    "CVE-2018-9274"
  );
  script_bugtraq_id(99085);

  script_name(english:"Wireshark 2.2.x < 2.2.14 / 2.4.x < 2.4.6 Multiple Vulnerabilities (MacOS)");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote MacOS / MacOSX host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote MacOS/MacOSX host
is 2.2.x prior to 2.2.14 or 2.4.x prior to 2.4.6. It is, therefore,
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-16.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-17.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-18.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-19.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-20.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-21.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-22.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-23.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.2.14 / 2.4.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9274");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("Host/MacOSX/Version");

app_info = vcf::get_app_info(app:"Wireshark");

constraints = [
  { "min_version" : "2.2.0", "fixed_version" : "2.2.14" },
  { "min_version" : "2.4.0", "fixed_version" : "2.4.6" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
