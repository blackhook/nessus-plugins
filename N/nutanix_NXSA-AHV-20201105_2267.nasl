#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164577);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2021-4034",
    "CVE-2021-20271",
    "CVE-2021-37750",
    "CVE-2021-41617",
    "CVE-2021-42574",
    "CVE-2021-43527",
    "CVE-2021-45417"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/18");

  script_name(english:"Nutanix AHV : Multiple Vulnerabilities (NXSA-AHV-20201105.2267)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20201105.2267. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AHV-20201105.2267 advisory.

  - A flaw was found in RPM's signature check functionality when reading a package file. This flaw allows an
    attacker who can convince a victim to install a seemingly verifiable package, whose signature header was
    modified, to cause RPM database corruption and execute code. The highest threat from this vulnerability is
    to data integrity, confidentiality, and system availability. (CVE-2021-20271)

  - The Key Distribution Center (KDC) in MIT Kerberos 5 (aka krb5) before 1.18.5 and 1.19.x before 1.19.3 has
    a NULL pointer dereference in kdc/do_tgs_req.c via a FAST inner body that lacks a server field.
    (CVE-2021-37750)

  - A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is
    a setuid tool designed to allow unprivileged users to run commands as privileged users according
    predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly
    and ends trying to execute environment variables as commands. An attacker can leverage this by crafting
    environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully
    executed the attack can cause a local privilege escalation given unprivileged users administrative rights
    on the target machine. (CVE-2021-4034)

  - sshd in OpenSSH 6.2 through 8.x before 8.8, when certain non-default configurations are used, allows
    privilege escalation because supplemental groups are not initialized as expected. Helper programs for
    AuthorizedKeysCommand and AuthorizedPrincipalsCommand may run with privileges associated with group
    memberships of the sshd process, if the configuration specifies running the command as a different user.
    (CVE-2021-41617)

  - ** DISPUTED ** An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through
    14.0. It permits the visual reordering of characters via control sequences, which can be used to craft
    source code that renders different logic than the logical ordering of tokens ingested by compilers and
    interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such
    that targeted vulnerabilities are introduced invisibly to human reviewers. NOTE: the Unicode Consortium
    offers the following alternative approach to presenting this concern. An issue is noted in the nature of
    international text that can affect applications that implement support for The Unicode Standard and the
    Unicode Bidirectional Algorithm (all versions). Due to text display behavior when text includes left-to-
    right and right-to-left characters, the visual order of tokens may be different from their logical order.
    Additionally, control characters needed to fully support the requirements of bidirectional text can
    further obfuscate the logical order of tokens. Unless mitigated, an adversary could craft source code such
    that the ordering of tokens perceived by human reviewers does not match what will be processed by a
    compiler/interpreter/etc. The Unicode Consortium has documented this class of vulnerability in its
    document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also
    provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode
    Security Mechanisms, and in Unicode Standard Annex #31, Unicode Identifier and Pattern Syntax. Also, the
    BIDI specification allows applications to tailor the implementation in ways that can mitigate misleading
    visual reordering in program text; see HL4 in Unicode Standard Annex #9, Unicode Bidirectional Algorithm.
    (CVE-2021-42574)

  - NSS (Network Security Services) versions prior to 3.73 or 3.68.1 ESR are vulnerable to a heap overflow
    when handling DER-encoded DSA or RSA-PSS signatures. Applications using NSS for handling signatures
    encoded within CMS, S/MIME, PKCS \#7, or PKCS \#12 are likely to be impacted. Applications using NSS for
    certificate validation or other TLS, X.509, OCSP or CRL functionality may be impacted, depending on how
    they configure NSS. *Note: This vulnerability does NOT impact Mozilla Firefox.* However, email clients and
    PDF viewers that use NSS for signature verification, such as Thunderbird, LibreOffice, Evolution and
    Evince are believed to be impacted. This vulnerability affects NSS < 3.73 and NSS < 3.68.1.
    (CVE-2021-43527)

  - AIDE before 0.17.4 allows local users to obtain root privileges via crafted file metadata (such as XFS
    extended attributes or tmpfs ACLs), because of a heap-based buffer overflow. (CVE-2021-45417)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20201105.2267
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7908d9f9");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43527");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Local Privilege Escalation in polkits pkexec');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:ahv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/Node/Version", "Host/Nutanix/Data/Node/Type");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info(node:TRUE);

var constraints = [
  { 'fixed_version' : '20201105.2267', 'product' : 'AHV', 'fixed_display' : 'Upgrade the AHV install to 20201105.2267 or higher.' }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
