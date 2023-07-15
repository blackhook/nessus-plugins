##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149023);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/20");

  script_cve_id(
    "CVE-2020-7463",
    "CVE-2021-1811",
    "CVE-2021-1825",
    "CVE-2021-1857"
  );
  script_xref(name:"APPLE-SA", value:"HT212319");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-04-21");

  script_name(english:"Apple iTunes < 12.11.3 Multiple Vulnerabilities (credentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is prior to 12.11.3. It is, therefore, affected by
multiple vulnerabilities as referenced in the HT212319 advisory.

  - In FreeBSD 12.1-STABLE before r364644, 11.4-STABLE before r364651, 12.1-RELEASE before p9, 11.4-RELEASE
    before p3, and 11.3-RELEASE before p13, improper handling in the kernel causes a use-after-free bug by
    sending large user messages from multiple threads on the same SCTP socket. The use-after-free situation
    may result in unintended kernel behaviour including a kernel panic. (CVE-2020-7463)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212319");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.11.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1857");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}
include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'iTunes Version', win_local:TRUE);
constraints = [{'fixed_version':'12.11.3'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
