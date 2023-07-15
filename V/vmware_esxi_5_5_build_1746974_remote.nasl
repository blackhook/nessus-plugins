#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(73917);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-0076", "CVE-2014-0160");
  script_bugtraq_id(66363, 66690);
  script_xref(name:"VMSA", value:"2014-0004");
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"ESXi 5.5 < Build 1746974 / 5.5 Update 1 < Build 1746018 OpenSSL Library Multiple Vulnerabilities (remote check) (Heartbleed)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.5 host is potentially affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is 5.5 prior to build 1746974 or 5.5
Update 1 prior to build 1746018. It is, therefore, potentially
affected by the following vulnerabilities in the OpenSSL library :

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - An out-of-bounds read error, known as the 'Heartbleed
    Bug', exists related to handling TLS heartbeat
    extensions that could allow an attacker to obtain
    sensitive information such as primary key material,
    secondary key material, and other protected content.
    (CVE-2014-0160");
  # https://kb.vmware.com/selfservice/microsites/search.do?cmd=displayKC&externalId=2076665
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?720c816b");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi550-201404420 for ESXi 5.5 or ESXi550-201404401 for
ESXi 5.5 Update 1.");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is (C) 2014-2023 Tenable Network Security, Inc.");

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
if ("VMware ESXi 5.5" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.5");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build = int(match[1]);
if (build == 1623387)
  fixed_build = 1746018;
else
  fixed_build = 1746974;;

if (build < 1746018)
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
else exit(0, "The host has "+ver+" build "+build+" and, therefore, is not affected.");
