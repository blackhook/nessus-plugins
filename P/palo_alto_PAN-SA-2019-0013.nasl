#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129302);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479");
  script_bugtraq_id(108798, 108801, 108818);
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"Palo Alto Networks PAN-OS 7.1.x < 7.1.24 / 8.0.x < 8.0.19 / 8.1.x < 8.1.8-h5 / 9.0.x < 9.0.2-h4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host is 7.1.x prior to 7.1.24 or 8.0.x prior to 8.0.19 or
8.1.x prior to 8.1.8-h5 or 9.0.x prior to 9.0.2-h4. It is, therefore, affected by  multiple vulnerabilities.

- An integer overflow condition exists in Linux kernel's networking subsystem processed TCP Selective Acknowledgment
  (SACK) segments. An unauthenticated, remote attacker can exploit this, via by sending a crafted sequence of SACK
  segments on a TCP connection with small value of TCP MSS, resulting in a denial of service (DoS) to cause a crash
  Linux kernel.(CVE-2019-11477)

- An excessive resource consumption flaw was found in the Linux kernel's networking subsystem processed TCP Selective
  Acknowledgment (SACK) segments. An unauthenticated, remote attacker can exploit this, via by sending a crafted
  sequence of SACK segments on a TCP connection, to cause a denial of service condition. (CVE-2019-11478)

- An excessive resource consumption flaw was found in the Linux kernel's networking subsystem processed TCP segments.
  An unauthenticated, remote attacker can exploit this, via repeatedly sending network traffic on TCP connection with
  low TCP MSS, resulting in a denial of service (Dos). (CVE-2019-11479)");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/151");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PAN-OS 7.1.24 / 8.0.19 / 8.1.8-h5 / 9.0.2-h4 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11477");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include('vcf.inc');

app_name = 'Palo Alto Networks PAN-OS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Palo_Alto/Firewall/Full_Version', kb_source:'Host/Palo_Alto/Firewall/Source');

constraints = [
  { 'min_version' : '7.1.0', 'max_version' : '7.1.23', 'fixed_display' : '7.1.24' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.18', 'fixed_display' : '8.0.19' },
  { 'min_version' : '8.1.0', 'max_version' : '8.1.8-h4', 'fixed_display' : '8.1.8-h5' },
  { 'min_version' : '9.0.0', 'max_version' : '9.0.2-h3', 'fixed_display' : '9.0.2-h4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);