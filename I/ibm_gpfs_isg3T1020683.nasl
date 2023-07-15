#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(74104);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-0076", "CVE-2014-0160");
  script_bugtraq_id(66363, 66690);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"IBM General Parallel File System 3.5 < 3.5.0.17 Multiple OpenSSL Vulnerabilities (Heartbleed)");

  script_set_attribute(attribute:"synopsis", value:
"A clustered file system on the remote host is affected by multiple
vulnerabilities related to OpenSSL.");
  script_set_attribute(attribute:"description", value:
"A version of IBM General Parallel File System (GPFS) prior to 3.5.0.17
is installed on the remote host. It is, therefore, affected by
multiple vulnerabilities related to OpenSSL:

  - An information disclosure vulnerability exists due to a
    flaw in the OpenSSL library, due to an implementation
    error in ECDSA (Elliptic Curve Digital Signature
    Algorithm). An attacker could potentially exploit this
    vulnerability to recover ECDSA nonces. (CVE-2014-0076)

  - An information disclosure vulnerability exists due to a
    flaw in the OpenSSL library, commonly known as the
    Heartbleed bug. An attacker could potentially exploit
    this vulnerability repeatedly to read up to 64KB of
    memory from the device. (CVE-2014-0160)");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=isg3T1020683");
  # https://www.ibm.com/blogs/psirt/security-bulletin-gpfs-v3-5-for-windows-is-affected-by-vulnerabilities-in-openssl-cve-2014-0160-and-cve-2014-0076/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20bb9fde");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 3.5.0.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0160");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:general_parallel_file_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_gpfs_installed.nbin");
  script_require_keys("SMB/ibm_gpfs/path", "SMB/ibm_gpfs/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "IBM General Parallel File System";
version = get_kb_item_or_exit("SMB/ibm_gpfs/version");
path = get_kb_item_or_exit("SMB/ibm_gpfs/path");

if (version =~ "^3\.5\.")
{
  fix = "3.5.0.17";
  if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
  {
    port = get_kb_item("SMB/transport");
    if (!port) port = 445;

    if (report_verbosity > 0)
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
      security_warning(extra:report, port:port);
    }
    else security_warning(port);
    exit(0);
  }
}

audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
