#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76368);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0198",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66801,
    67193,
    67898,
    67899
  );
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"VMSA", value:"2014-0006");

  script_name(english:"ESXi 5.0 < Build 1918656 OpenSSL Library Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.0 host is affected by multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.0 prior to build 1918656. It
is, therefore, affected by the following vulnerabilities in the
OpenSSL library :

  - An error exists in the function 'ssl3_read_bytes'
    that could allow data to be injected into other
    sessions or allow denial of service attacks. Note
    this issue is only exploitable if
    'SSL_MODE_RELEASE_BUFFERS' is enabled. (CVE-2010-5298)

  - An error exists in the function 'do_ssl3_write' that
    could allow a NULL pointer to be dereferenced leading
    to denial of service attacks. Note this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    ciphersuites that could allow denial of service
    attacks. Note this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0006.html");
  # https://kb.vmware.com/selfservice/microsites/search.do?cmd=displayKC&externalId=2078807
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7cdd0f9");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi500-201407001 for ESXi 5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");

if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");
if ("VMware ESXi 5.0" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.0");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build = int(match[1]);
fixed_build = 1918656;

if (build < fixed_build)
{
  if (report_verbosity > 0)
  {
    report = '\n  ESXi version    : ' + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fixed_build +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver - "ESXi " + " build " + build);
