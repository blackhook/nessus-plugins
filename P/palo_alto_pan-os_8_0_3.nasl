#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101164);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id(
    "CVE-2016-8610",
    "CVE-2016-10229",
    "CVE-2017-8390",
    "CVE-2017-9458",
    "CVE-2017-9459",
    "CVE-2017-9467",
    "CVE-2017-12416"
  );
  script_bugtraq_id(
    93841,
    97397,
    99902,
    99907,
    99911,
    100614,
    100619
  );

  script_name(english:"Palo Alto Networks PAN-OS 6.1.x < 6.1.18 / 7.0.x < 7.0.17 / 7.1.x < 7.1.12 / 8.0.x < 8.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
6.1.x prior to 6.1.18, 7.0.x prior to 7.0.17, 7.1.x prior to 7.1.12,
or 8.0.x prior to 8.0.3. It is, therefore, affected by multiple
vulnerabilities :

  - A denial of service vulnerability exists in the OpenSSL
    component that is triggered when handling a large number
    of consecutive 'SSL3_AL_WARNING' undefined alerts. An
    unauthenticated, remote attacker can exploit this, by
    continuously sending warning alerts, to exhaust
    available CPU resources. Note that this vulnerability
    does not affect the 8.0.x version branch.
    (CVE-2016-8610)

  - A remote code execution vulnerability exists in the
    Linux kernel in udp.c due to an unsafe second checksum
    calculation during execution of a recv system call with
    the MSG_PEEK flag. An unauthenticated, remote attacker
    can exploit this, via specially crafted UDP traffic, to
    cause a denial of service condition or the execution of
    arbitrary code. Note that this vulnerability does not
    affect the 7.0.x version branch. (CVE-2016-10229)

  - A remote code execution vulnerability exists in the DNS
    proxy service that is triggered when resolving fully
    qualified domain names (FQDN). An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. Note that this vulnerability was fixed in version
    7.1.10 for the 7.1.x version branch. (CVE-2017-8390)

  - A XML external entity (XXE) vulnerability exists due to
    an incorrectly configured XML parser accepting XML from
    an untrusted source. An unauthenticated, remote attacker
    can exploit this by sending specially crafted XML data
    to the GlobalProtect external interface. Exploitation of
    this vulnerability may allow disclosure of information,
    denial of service or server side request forgery.
    (CVE-2017-9458)

  - A stored cross-site scripting (XSS) vulnerability exists
    in the Firewall web interface due to improper validation
    of user-supplied input before returning it to users. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2017-9459)

  - A cross-site scripting (XSS) vulnerability exists in the
    GlobalProtect component due to improper validation of
    user-supplied input to unspecified request parameters.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code in a user's browser session.
    (CVE-2017-9467, CVE-2017-12416)

  - A denial of service vulnerability exists that is
    triggered when the system attempts to close the
    connection of a rogue client that ignored the URL
    filtering block page. An unauthenticated, remote
    attacker can exploit this to crash the interface. Note
    that this vulnerability does not affect the 6.1.x and
    7.0.x version branches.");
  # https://www.paloaltonetworks.com/documentation/80/pan-os/pan-os-release-notes/pan-os-8-0-3-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d557f3a");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/87");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/88");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/89");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/90");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/91");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/93");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/94");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 6.1.18 / 7.0.17 / 7.1.12
/ 8.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10229");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version", "Host/Palo_Alto/Firewall/Source");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::palo_alto::initialize();

app_name = 'Palo Alto Networks PAN-OS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Palo_Alto/Firewall/Full_Version', kb_source:'Host/Palo_Alto/Firewall/Source');

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '6.1', 'max_version' : '6.1.17', 'fixed_version' : '6.1.18' },
  { 'min_version' : '7.0', 'max_version' : '7.0.16', 'fixed_version' : '7.0.17' },
  { 'min_version' : '7.1', 'max_version' : '7.1.11', 'fixed_version' : '7.1.12' },
  { 'min_version' : '8.0', 'max_version' : '8.0.2', 'fixed_version' : '8.0.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE,flags:{xss:TRUE});
