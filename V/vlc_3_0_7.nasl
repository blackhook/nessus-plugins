#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126246);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-5439",
    "CVE-2019-12874",
    "CVE-2019-5460",
    "CVE-2019-5459"
  );
  script_bugtraq_id(108769, 108882);
  script_xref(name:"CEA-ID", value:"CEA-2019-0487");

  script_name(english:"VLC < 3.0.7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by a
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote host is earlier
than 3.0.7.  It is, therefore, affected by multiple vulnerabilities:

  - A heap-based buffer overflow condition exists in ReadFrame 
    due to improper parsing of AVI files. A remote attacker can 
    exploit this by tricking a user into opening a specially 
    crafted avi file to cause a denial of service condition 
    or the execution of arbitrary code.(CVE-2019-5439)

  - A double free vulnerability exists in zlib_decompress_extra
    due to improper parsing of MKV files. A remote attacker can 
    exploit this by tricking a user into opening a specially 
    crafted MKV file to cause a denial of service condition 
    or the execution of arbitrary code.(CVE-2019-12874)

  - An Integer underflow in VLC Media Player versions < 3.0.7 
    leads to an out-of-band read..(CVE-2019-5459)

  - A double free vulnerability exists which lead to VLC application to crash.
    (CVE-2019-5460)");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/developers/vlc-branch/NEWS");
  script_set_attribute(attribute:"see_also", value:"https://www.videolan.org/security/sa1901.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 3.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12874");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"VLC media player", win_local:TRUE);

constraints = [{"fixed_version":"3.0.7"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
