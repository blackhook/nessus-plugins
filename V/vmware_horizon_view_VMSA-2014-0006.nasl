#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76945);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66801,
    67193,
    67898,
    67899,
    67900,
    67901
  );
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"VMSA", value:"2014-0006");

  script_name(english:"VMware Horizon View Multiple Vulnerabilities (VMSA-2014-0006)");
  script_summary(english:"Checks the version of VMware Horizon View.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon View installed on the remote Windows
host is version 5.3.x prior to 5.3.2 or 5.3.x prior to 5.3 Feature
Pack 3. It is, therefore, affected by multiple vulnerabilities in the
bundled OpenSSL library :

  - An error exists in the function 'ssl3_read_bytes'
    that could allow data to be injected into other
    sessions or allow denial of service attacks. Note
    this issue is only exploitable if
    'SSL_MODE_RELEASE_BUFFERS' is enabled. (CVE-2010-5298)

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
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000259.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0006.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Horizon View 5.3.2 / 5.3 Feature Pack 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_horizon_view_installed.nbin");
  script_require_keys("installed_sw/VMware Horizon View");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "VMware Horizon View";
get_install_count(app_name:"VMware Horizon View", exit_if_zero:TRUE);
report = NULL;

install = get_single_install(app_name:"VMware Horizon View");

path = install['path'];
version = install['version'];

if ("Server" >< install['Install type'])
{
  fix = "5.3.2";
  if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
  }
}
else if ("Agent" >< install['Install type'])
{
  fp_version = install['Feature pack'];
  if (version =~ "^5\." && !isnull(fp_version))
  {
    fix = "5.3";
    fp_fix = "3.0.9231";
    if (
      ver_compare(ver:version, fix:fix, strict:FALSE) == -1 ||
      ver_compare(ver:fp_version, fix:fp_fix, strict:FALSE) == -1
    )
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version + " Feature Pack " + fp_version +
        '\n  Fixed version     : ' + fix + " Feature Pack " + fp_fix +
        '\n';
    }
  }
}

if (!isnull(report))
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0) security_warning(extra:report, port:port);
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
