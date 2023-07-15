#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135032);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-3885",
    "CVE-2020-3887",
    "CVE-2020-3894",
    "CVE-2020-3895",
    "CVE-2020-3897",
    "CVE-2020-3899",
    "CVE-2020-3900",
    "CVE-2020-3901",
    "CVE-2020-3902",
    "CVE-2020-3909",
    "CVE-2020-3910",
    "CVE-2020-3911",
    "CVE-2020-9783"
  );
  script_xref(name:"APPLE-SA", value:"HT211105");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-03-20");

  script_name(english:"Apple iTunes < 12.10.5 Multiple Vulnerabilities (credentialed check) (HT211105)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is prior to 12.10.5. It is, therefore, affected by
multiple vulnerabilities as referenced in the HT211105 advisory. Note that Nessus has not tested for this issue but has
instead relied only on the application's self-reported version number.


  - A buffer overflow issue in libxm12 had issues with size validation and buffer overflow. 
    (CVE-2020-3910, CVE-2020-3909, CVE-2020-3911)

  - A type confusion issue in WebKit could lead to the execution of malicious crafted code 
    (CVE-2020-3901)

  - A Memory corruption issue in WebKit could cause a arbitary code execution vulnerability 
    (CVE-2020-3895, CVE-2020-3900)

   Additional vulnerabilities are detailed HT211105 in the advisory.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211105");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.10.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3899");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-3911");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}
include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'iTunes Version', win_local:TRUE);
constraints = [{'fixed_version':'12.10.5'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
