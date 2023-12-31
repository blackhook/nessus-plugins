#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77020);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0076",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66363,
    66801,
    67193,
    67898,
    67899,
    67900,
    67901
  );
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"HP", value:"emr_na-c04379485");
  script_xref(name:"HP", value:"HPSBMU03076");
  script_xref(name:"HP", value:"SSRT101648");

  script_name(english:"HP Systems Insight Manager 7.2.x < 7.2 Hotfix 37 / 7.3.x < 7.3 Hotfix 34 OpenSSL Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP Systems Insight Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains software that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Systems Insight Manager installed on the remote
Windows host is affected by the following vulnerabilities in the
included OpenSSL library :

  - An error exists in the function 'ssl3_read_bytes'
    that could allow data to be injected into other
    sessions or allow denial of service attacks. Note
    this issue is only exploitable if
    'SSL_MODE_RELEASE_BUFFERS' is enabled. (CVE-2010-5298)

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that could lead to execution of
    arbitrary code. Note this issue only affects OpenSSL
    when used as a DTLS client or server. (CVE-2014-0195)

  - An error exists in the function 'do_ssl3_write' that
    could allow a NULL pointer to be dereferenced leading
    to denial of service attacks. Note this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    could lead to denial of service attacks. Note this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    cipher suites that could allow denial of service
    attacks. Note this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470)");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c04379485
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5151aa42");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/532878/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Hotfix kit mentioned in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:systems_insight_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_systems_insight_manager_installed.nasl");
  script_require_keys("installed_sw/HP Systems Insight Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

app_name = "HP Systems Insight Manager";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

install = get_single_install(app_name:app_name);
path = install['path'];
version = install['version'];

hotfixes = install['Hotfixes'];
if (isnull(hotfixes)) hotfixes = "n/a";
else hotfixes = str_replace(string:hotfixes, find:";", replace:", ");

fixed_hotfix = NULL;

# 7.2.0, 7.2.1, 7.2.2
if (version =~ "^(([A-Z]\.)?07\.([A-C]\.)?(02\.0[0-2])\.[0-9a-z.]+)")
  fixed_hotfix = "HOTFIX72_037";
# 7.3.0, 7.3.0a, 7.3.1
else if (version =~ "^(([A-Z]\.)?07\.([A-C]\.)?(03\.0[01a])\.[0-9a-z.]+)")
  fixed_hotfix = "HOTFIX73_034";
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

if (fixed_hotfix >!< hotfixes)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path               : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Installed hotfixes : ' + hotfixes +
      '\n  Fixed hotfix       : ' + fixed_hotfix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
