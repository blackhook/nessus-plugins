#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(73674);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-0076", "CVE-2014-0160");
  script_bugtraq_id(66363, 66690);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"VMSA", value:"2014-0004");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"VMware Workstation 10.x < 10.0.2 OpenSSL Library Multiple Vulnerabilities (VMSA-2014-0004) (Heartbleed)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is
version 10.x prior to 10.0.2.  It is, therefore, reportedly affected
by the following vulnerabilities in the OpenSSL library :

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - An out-of-bounds read error, known as the 'Heartbleed
    Bug', exists related to handling TLS heartbeat
    extensions that could allow an attacker to obtain
    sensitive information such as primary key material,
    secondary key material and other protected content.
    (CVE-2014-0160)");
  # https://kb.vmware.com/selfservice/microsites/search.do?cmd=displayKC&externalId=2076225
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03fa22fa");
  # https://www.vmware.com/support/ws10/doc/workstation-1002-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a48b929");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation 10.0.2 or later.");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("VMware/Workstation/Version", "VMware/Workstation/Path");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '10.0', 'fixed_version' : '10.0.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
