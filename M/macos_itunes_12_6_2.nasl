#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101956);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-7010",
    "CVE-2017-7012",
    "CVE-2017-7013",
    "CVE-2017-7018",
    "CVE-2017-7019",
    "CVE-2017-7020",
    "CVE-2017-7030",
    "CVE-2017-7034",
    "CVE-2017-7037",
    "CVE-2017-7039",
    "CVE-2017-7040",
    "CVE-2017-7041",
    "CVE-2017-7042",
    "CVE-2017-7043",
    "CVE-2017-7046",
    "CVE-2017-7048",
    "CVE-2017-7049",
    "CVE-2017-7052",
    "CVE-2017-7053",
    "CVE-2017-7055",
    "CVE-2017-7056",
    "CVE-2017-7061",
    "CVE-2017-7064"
  );
  script_bugtraq_id(
    99879,
    99884,
    99885,
    99889,
    99890
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-07-19-6");

  script_name(english:"Apple iTunes < 12.6.2 Multiple Vulnerabilities (macOS) (credentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote macOS or Mac OS X
host is prior to 12.6.2. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple out-of-bounds read errors exist in the libxml2
    component due to improper handling of specially crafted
    XML documents. An unauthenticated, remote attacker can
    exploit these to disclose user information.
    (CVE-2017-7010, CVE-2017-7013)

  - Multiple memory corruption issues exist in the Webkit
    Web Inspector component due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit these, via a specially crafted web page, to
    corrupt memory, resulting in the execution of arbitrary
    code. (CVE-2017-7012)

  - Multiple memory corruption issues exist in the WebKit
    component due to improper validation of input. An
    unauthenticated, remote attacker can exploit these
    issues, via a specially crafted web page, to execute
    arbitrary code. (CVE-2017-7018, CVE-2017-7020,
    CVE-2017-7030, CVE-2017-7034, CVE-2017-7037,
    CVE-2017-7039, CVE-2017-7040, CVE-2017-7041,
    CVE-2017-7042, CVE-2017-7043, CVE-2017-7046,
    CVE-2017-7048, CVE-2017-7049, CVE-2017-7052,
    CVE-2017-7055, CVE-2017-7056, CVE-2017-7061)

  - A memory corruption issue exists in the 'WebKit Page
    Loading' component due to improper validation of input.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted web page, to execute arbitrary
    code. (CVE-2017-7019)

  - A flaw exists in the iPodService component when handling
    the iPodManager COM control due to insufficient access
    restrictions. A local attacker can exploit this to
    execute arbitrary code with system privileges.
    (CVE-2017-7053)

  - An unspecified memory initialization issue exists in
    Webkit. A local attacker can exploit this, via a
    specially crafted application, to disclose the contents
    of restricted memory. (CVE-2017-7064)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207928");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7053");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_itunes_detect.nasl");
  script_require_keys("Host/MacOSX/Version", "installed_sw/iTunes");

  exit(0);
}

include("vcf.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"iTunes");

constraints = [{"fixed_version" : "12.6.2"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
