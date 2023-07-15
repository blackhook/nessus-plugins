#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173835);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id("CVE-2022-3602", "CVE-2022-3786");
  script_xref(name:"JSA", value:"JSA69999");
  script_xref(name:"CEA-ID", value:"CEA-2022-0036");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA69999)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA69999 advisory.

  - A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed a malicious certificate or for an application to continue certificate verification despite
    failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a
    certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the
    stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this
    can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server
    requests client authentication and a malicious client connects. (CVE-2022-3786)

  - A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed the malicious certificate or for the application to continue certificate verification despite
    failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to
    overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash
    (causing a denial of service) or potentially remote code execution. Many platforms implement stack
    overflow protections which would mitigate against the risk of remote code execution. The risk may be
    further mitigated based on stack layout for any given platform/compiler. Pre-announcements of
    CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors
    described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new
    version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server.
    In a TLS server, this can be triggered if the server requests client authentication and a malicious client
    connects. (CVE-2022-3602)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2023-01-Security-Bulletin-Junos-OS-vSRX-Series-A-memory-leak-might-be-observed-in-IPsec-VPN-scenario-leading-to-an-FPC-crash-CVE-2023-22417
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a391b314");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70213");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [ {'min_ver':'22.1', 'fixed_ver':'22.1R1-EVO', 'fixed_display':'22.1R1-EVO or later.'} ];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);

if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
