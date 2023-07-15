#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(90148);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/05");

  script_cve_id("CVE-2015-3184", "CVE-2015-3187", "CVE-2016-1765");
  script_bugtraq_id(76273, 76274);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-03-21-4");

  script_name(english:"Apple Xcode < 7.3 Multiple Vulnerabilities (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Xcode installed on the remote Mac OS X host is prior to 7.3. It is, therefore, affected by
multiple vulnerabilities :

  - A flaw exists in Apache Subversion in mod_authz_svn due to a failure to properly restrict anonymous
    access. An unauthenticated, remote attacker can exploit this, via a crafted path name, to read hidden
    files. (CVE-2015-3184)

  - A flaw exists in Apache Subversion in the svn_repos_trace_node_locations() function that causes the first
    readable path to be returned when it encounters an unreadable path when following a node's history. An
    authenticated, remote attacker can exploit this to access paths that were intended to be hidden.
    (CVE-2015-3187)

  - Multiple unspecified memory corruption issues exist in otool due to improper validation of user-supplied
    input. A local attacker can exploit these to cause a denial of service or to execute arbitrary code.
    (CVE-2016-1765)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-ca/HT206172");
  # https://lists.apple.com/archives/security-announce/2016/Mar/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a264ce9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3184");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_xcode_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Apple Xcode");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os))
  audit(AUDIT_OS_NOT, 'macOS or Mac OS X');

app_info = vcf::get_app_info(app:'Apple Xcode');

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'fixed_version' : '7.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
