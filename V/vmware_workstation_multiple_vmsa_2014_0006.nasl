#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76456);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

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

  script_name(english:"VMware Workstation < 9.0.4 / 10.0.3 OpenSSL Library Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is
version 9.x prior to 9.0.4 or 10.x prior to 10.0.3. It is, therefore,
affected by the following vulnerabilities in the OpenSSL library :

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
  # http://lists.vmware.com/pipermail/security-announce/2014/000253.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4357b8a5");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0006.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2010-5298");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0198");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0224");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-3470");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation 9.0.4 / 10.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Workstation/Version", "VMware/Workstation/Path");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '9.0', 'fixed_version' : '9.0.4'},
  { 'min_version' : '10.0', 'fixed_version' : '10.0.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
