#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76994);
  script_version("1.7");
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

  script_name(english:"VMware vCenter Support Assistant Multiple Vulnerabilities (VMSA-2014-0006)");
  script_summary(english:"Checks the version of VMware vCenter Support Assistant.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a support tool installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Support Assistant installed on the
remote host is 5.5.1.x prior to 5.5.1.1. It is, therefore, affected by
multiple vulnerabilities in the bundled OpenSSL library :

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
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0006.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Support Assistant 5.5.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vCenter Support Assistant/Version", "Host/VMware vCenter Support Assistant/Build");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware vCenter Support Assistant/Version");
build = get_kb_item_or_exit("Host/VMware vCenter Support Assistant/Build");

if (version =~ '^5\\.5\\.1([^0-9]|$)' && ver_compare(ver:version, fix:'5.5.1.1', strict:FALSE) == -1)
{
  if (report_verbosity> 0)
  {
    report =
      '\n  Installed version : ' + version + ' Build ' + build +
      '\n  Fixed version     : 5.5.1.1 Build 1929337\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vCenter Support Assistant', version + ' Build ' + build);
