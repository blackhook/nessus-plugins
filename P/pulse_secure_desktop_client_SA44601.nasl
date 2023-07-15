##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142056);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/03");

  script_cve_id(
    "CVE-2020-8239",
    "CVE-2020-8240",
    "CVE-2020-8241",
    "CVE-2020-8254",
    "CVE-2020-8956"
  );
  script_xref(name:"IAVA", value:"2020-A-0495");

  script_name(english:"Pulse Secure Desktop Client < 9.1R9 Multiple Vulnerabilities (SA44601)");

  script_set_attribute(attribute:"synopsis", value:
"A VPN client installed on the remote windows system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Pulse Secure Desktop Client installed on the remote Windows system is prior to 9.1R9. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - A vulnerability in the Pulse Secure Desktop Client < 9.1R9 could allow the attacker to perform a MITM
    Attack if end users are convinced to connect to a malicious server. (CVE-2020-8241)

  - A vulnerability in the Pulse Secure Desktop Client < 9.1R9 allows a restricted user on an endpoint machine
    can use system-level privileges if the Embedded Browser is configured with Credential Provider. This
    vulnerability only affects Windows PDC if the Embedded Browser is configured with the Credential Provider.
    (CVE-2020-8240)

  - A vulnerability in the Pulse Secure Desktop Client < 9.1R9 has Remote Code Execution (RCE) if users can be
    convinced to connect to a malicious server. This vulnerability only affects Windows PDC.To improve the
    security of connections between Pulse clients and Pulse Connect Secure, see below recommendation(s):
    Disable Dynamic certificate trust for PDC. (CVE-2020-8254)


Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44601");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Secure Desktop Client 9.1R9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8239");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_secure_desktop_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("juniper_pulse_client_installed.nbin");
  script_require_keys("installed_sw/Pulse Secure Desktop Client");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Pulse Secure Desktop Client', win_local:TRUE);

constraints = [
  {'fixed_version':'9.1.9', 'fixed_display':'9.1R9'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

