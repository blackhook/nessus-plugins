#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153948);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/09");

  script_cve_id("CVE-2021-31986", "CVE-2021-31987", "CVE-2021-31988");
  script_xref(name:"IAVA", value:"2021-A-0452");

  script_name(english:"AXIS OS 5.51 < 5.51.7.5 / 6.0 < 6.50.5.5 / 7.0 < 8.40.4.3 / 9.0 < 9.80.3.5 / 10.0 < 10.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The firmware version running on the remote host is vulnerable to multiple vulnerabilities, including the following:

  - User controlled parameters related to SMTP notifications are not correctly validated. This can lead to a
    buffer overflow resulting in crashes and data leakage. (CVE-2021-31986)

  - A user controlled parameter related to SMTP test functionality is not correctly validated making it
    possible to bypass blocked network recipients. (CVE-2021-31987)

  - A user controlled parameter related to SMTP test functionality is not correctly validated making it
    possible to add the Carriage Return and Line Feed (CRLF) control characters and include arbitrary SMTP
    headers in the generated test email. (CVE-2021-31988)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.zdnet.com/article/axis-releases-updates-for-three-new-vulnerabilities-found-by-security-company/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?342a9fe7");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?675da90e");
  script_set_attribute(attribute:"see_also", value:"https://www.axis.com/files/tech_notes/CVE-2021-31988.pdf");
  script_set_attribute(attribute:"see_also", value:"https://www.axis.com/files/tech_notes/cve-2021-31987.pdf");
  script_set_attribute(attribute:"see_also", value:"https://www.axis.com/files/tech_notes/CVE-2021-31986.pdf");

  script_set_attribute(attribute:"solution", value:
"Upgrade the host firmware..");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31988");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:axis:network_camera_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("axis_www_detect.nbin", "axis_ftp_detect.nbin");
  script_require_keys("installed_sw/AXIS device");
  script_require_ports("Services/www", "Services/ftp", 80, 21);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::axis::get_app_info();

var constraints = [
  {'min_version' : '5.51', 'fixed_version' : '5.51.7.5'},
  {'min_version' : '6.0', 'fixed_version' : '6.50.5.5'},
  {'min_version' : '7.0',  'fixed_version' : '8.40.4.3'},
  {'min_version' : '9.0',  'fixed_version' : '9.80.3.5'},
  {'min_version' : '10.0', 'fixed_version' : '10.8'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
