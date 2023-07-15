#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134305);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-1559");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Palo Alto Networks PAN-OS 7.1 < 7.1.25 / 8.0 < 8.0.20 / 8.1 < 8.1.8 / 9.0 < 9.0.2 OpenSSL Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by a cryptographic vulnerability");
  script_set_attribute(attribute:"description", value:
"If an application encounters a fatal protocol error and then calls SSL_shutdown() twice (once to send a close_notify, 
and once to receive one) then OpenSSL can respond differently to the calling application if a 0 byte record is received
with invalid padding compared to if a 0 byte record is received with an invalid MAC. If the application then behaves 
differently based on that in a way that is detectable to the remote peer, then this amounts to a padding oracle that 
could be used to decrypt data. In order for this to be exploitable 'non-stitched' ciphersuites must be in use. Stitched
ciphersuites are optimised implementations of certain commonly used ciphersuites. Also the application must call 
SSL_shutdown() twice even if a protocol error has occurred (applications should not do this but some do anyway).

PAN-OS version 7.0 and prior EOL versions have not been evaluated for this issue, and thus, may also be affected.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.paloaltonetworks.com/CVE-2019-1559");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PAN-OS 7.1.25 / 8.0.20 / 8.1.8 / 9.0.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1559");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include('vcf.inc');

app_name = 'Palo Alto Networks PAN-OS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Palo_Alto/Firewall/Full_Version', kb_source:'Host/Palo_Alto/Firewall/Source');

constraints = [
  { 'min_version' : '0.0.0', 'fixed_version' : '7.1.25' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.20' },
  { 'min_version' : '8.1.0', 'fixed_version' : '8.1.8' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
