##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162418);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/05");

  script_cve_id("CVE-2022-2068");
  script_xref(name:"IAVA", value:"2022-A-0257-S");

  script_name(english:"OpenSSL 3.0.0 < 3.0.4 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 3.0.4. It is, therefore, affected by a vulnerability as
referenced in the 3.0.4 advisory.

  - In addition to the c_rehash shell command injection identified in CVE-2022-1292, further circumstances
    where the c_rehash script does not properly sanitise shell metacharacters to prevent command injection
    were found by code review. When the CVE-2022-1292 was fixed it was not discovered that there are other
    places in the script where the file names of certificates being hashed were possibly passed to a command
    executed through the shell. This script is distributed by some operating systems in a manner where it is
    automatically executed. On such operating systems, an attacker could execute arbitrary commands with the
    privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the
    OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.4 (Affected 3.0.0,3.0.1,3.0.2,3.0.3). Fixed in
    OpenSSL 1.1.1p (Affected 1.1.1-1.1.1o). Fixed in OpenSSL 1.0.2zf (Affected 1.0.2-1.0.2ze). (CVE-2022-2068)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cve.org/CVERecord?id=CVE-2022-2068");
  # https://github.com/openssl/openssl/commit/2c9c35870601b4a44d86ddbf512b38df38285cfa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6569bd51");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20220621.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 3.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("openssl/port", "installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [{ 'min_version' : '3.0.0', 'fixed_version' : '3.0.4'}];

vcf::openssl::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
