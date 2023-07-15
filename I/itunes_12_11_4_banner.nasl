#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152752);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-30779", "CVE-2021-30785");
  script_xref(name:"APPLE-SA", value:"HT212609");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-08-10");

  script_name(english:"Apple iTunes < 12.11.4 Multiple Vulnerabilities (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is prior to 12.11.4. It is, therefore, affected by
multiple vulnerabilities as referenced in the HT212609 advisory.

  - A buffer overflow was addressed with improved bounds checking. This issue is fixed in iOS 14.7, macOS Big
    Sur 11.5, watchOS 7.6, tvOS 14.7, Security Update 2021-004 Catalina. Processing a maliciously crafted
    image may lead to arbitrary code execution. (CVE-2021-30785)

  - This issue was addressed with improved checks. This issue is fixed in iOS 14.7, macOS Big Sur 11.5,
    watchOS 7.6, tvOS 14.7. Processing a maliciously crafted image may lead to arbitrary code execution.
    (CVE-2021-30779)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212609");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.11.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30785");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("installed_sw/iTunes DAAP");
  script_require_ports("Services/www", 3689);

  exit(0);
}
include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('vcf.inc');

app = 'iTunes DAAP';
port = get_http_port(default:3689, embedded:TRUE, ignore_broken:TRUE);

app_info = vcf::get_app_info(app:app, port:port);
if (app_info.Type != 'Windows') audit(AUDIT_OS_NOT, 'Windows');
constraints = [{'fixed_version':'12.11.4'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
