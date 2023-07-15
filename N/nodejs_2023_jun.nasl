#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177518);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2023-30581",
    "CVE-2023-30582",
    "CVE-2023-30583",
    "CVE-2023-30584",
    "CVE-2023-30585",
    "CVE-2023-30586",
    "CVE-2023-30587",
    "CVE-2023-30588",
    "CVE-2023-30589",
    "CVE-2023-30590"
  );
  script_xref(name:"IAVB", value:"2023-B-0042");

  script_name(english:"Node.js 16.x < 16.20.1 / 18.x < 18.16.1 / 20.x < 20.3.1 Multiple Vulnerabilities (Tuesday June 20 2023 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 16.20.1, 18.16.1, 20.3.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the Tuesday June 20 2023 Security Releases advisory.

  - The use of proto in process.mainModule.proto.require() can bypass the policy mechanism and require modules
    outside of the policy.json definition. This vulnerability affects all users using the experimental policy
    mechanism in all active release lines: 16.x, 18.x and, 20.x. Please note that at the time this CVE was
    issued, the policy is an experimental feature of Node.js. Thank you, to Axel Chong for reporting this
    vulnerability and thank you Rafael Gonzaga for fixing it. (CVE-2023-30581)

  - A vulnerability has been discovered in Node.js version 20, specifically within the experimental permission
    model. This flaw relates to improper handling of path traversal bypass when verifying file permissions.
    This vulnerability affects all users using the experimental permission model in Node.js 20. Please note
    that at the time this CVE was issued, the permission model is an experimental feature of Node.js. Thank
    you, to Axel Chong for reporting this vulnerability and thank you Rafael Gonzaga for fixing it.
    (CVE-2023-30584)

  - A vulnerability in Node.js version 20 allows for bypassing restrictions set by the --experimental-
    permission flag using the built-in inspector module (node:inspector). By exploiting the Worker class's
    ability to create an internal worker with the kIsInternal Symbol, attackers can modify the isInternal
    value when an inspector is attached within the Worker constructor before initializing a new WorkerImpl.
    This vulnerability exclusively affects Node.js users employing the permission model mechanism in Node.js
    20. Please note that at the time this CVE was issued, the permission model is an experimental feature of
    Node.js. Thank you, to mattaustin for reporting this vulnerability and thank you Rafael Gonzaga for fixing
    it. (CVE-2023-30587)

  - A vulnerability has been identified in Node.js version 20, affecting users of the experimental permission
    model when the --allow-fs-read flag is used with a non-* argument. This flaw arises from an inadequate
    permission model that fails to restrict file watching through the fs.watchFile API. As a result, malicious
    actors can monitor files that they do not have explicit read access to. This vulnerability affects all
    users using the experimental permission model in Node.js 20. Please note that at the time this CVE was
    issued, the permission model is an experimental feature of Node.js. Thanks to Colin Ihrig for reporting
    this vulnerability and to Rafael Gonzaga for fixing it. (CVE-2023-30582)

  - fs.openAsBlob() can bypass the experimental permission model when using the file system read restriction
    with the --allow-fs-read flag in Node.js 20. This flaw arises from a missing check in the fs.openAsBlob()
    API. This vulnerability affects all users using the experimental permission model in Node.js 20. Thanks to
    Colin Ihrig for reporting this vulnerability and to Rafael Gonzaga for fixing it. Please note that at the
    time this CVE was issued, the permission model is an experimental feature of Node.js. (CVE-2023-30583)

  - A vulnerability has been identified in the Node.js (.msi version) installation process, specifically
    affecting Windows users who install Node.js using the .msi installer. This vulnerability emerges during
    the repair operation, where the msiexec.exe process, running under the NT AUTHORITY\SYSTEM context,
    attempts to read the %USERPROFILE% environment variable from the current user's registry. The issue arises
    when the path referenced by the %USERPROFILE% environment variable does not exist. In such cases, the
    msiexec.exe process attempts to create the specified path in an unsafe manner, potentially leading to
    the creation of arbitrary folders in arbitrary locations. The severity of this vulnerability is heightened
    by the fact that the %USERPROFILE% environment variable in the Windows registry can be modified by
    standard (or non-privileged) users. Consequently, unprivileged actors, including malicious entities or
    trojans, can manipulate the environment variable key to deceive the privileged msiexec.exe process. This
    manipulation can result in the creation of folders in unintended and potentially malicious locations. It
    is important to note that this vulnerability is specific to Windows users who install Node.js using the
    .msi installer. Users who opt for other installation methods are not affected by this particular issue.
    This affects all active Node.js versions: v16, v18, and, v20. Thank you, to @sim0nsecurity for reporting
    this vulnerability and thank you Tobias Nieen for fixing it. (CVE-2023-30585)

  - Node.js 20 allows loading arbitrary OpenSSL engines when the experimental permission model is enabled,
    which can bypass and/or disable the permission model. The crypto.setEngine() API can be used to bypass the
    permission model when called with a compatible OpenSSL engine. The OpenSSL engine can, for example,
    disable the permission model in the host process by manipulating the process's stack memory to locate the
    permission model Permission::enabled_ in the host process's heap memory. This vulnerability affects all
    users using the experimental permission model in Node.js 20. Please note that at the time this CVE was
    issued, the permission model is an experimental feature of Node.js. Thanks to Tobias Nieen for reporting
    this vulnerability and fixing it. (CVE-2023-30586)

  - When an invalid public key is used to create an x509 certificate using the crypto.X509Certificate() API a
    non-expect termination occurs making it susceptible to DoS attacks when the attacker could force
    interruptions of application processing, as the process terminates when accessing public key info of
    provided certificates from user code. The current context of the users will be gone, and that will cause a
    DoS scenario. This vulnerability affects all active Node.js versions v16, v18, and, v20. Thank you, to
    Marc Schnefeld for reporting this vulnerability and thank you Tobias Nieen for fixing it.
    (CVE-2023-30588)

  - The llhttp parser in the http module in Node.js does not strictly use the CRLF sequence to delimit HTTP
    requests. This can lead to HTTP Request Smuggling (HRS). The CR character (without LF) is sufficient to
    delimit HTTP header fields in the llhttp parser. According to RFC7230 section 3, only the CRLF sequence
    should delimit each header-field. This vulnerability impacts all Node.js active versions: v16, v18, and,
    v20. Thank you, to Yadhu Krishna M(Team bi0s & CRED Security team) for reporting this vulnerability and
    thank you Paolo Insogna for fixing it. (CVE-2023-30589)

  - The generateKeys() API function returned from crypto.createDiffieHellman() only generates missing (or
    outdated) keys, that is, it only generates a private key if none has been set yet. However, the
    documentation says this API call: Generates private and public Diffie-Hellman key values. The documented
    behavior is different from the actual behavior, and this difference could easily lead to security issues
    in applications that use these APIs as the DiffieHellman may be used as the basis for application-level
    security. Please note that this is a documentation change an the vulnerability has been classified under
    CWE-1068 - Inconsistency Between Implementation and Documented Design. This change applies to all Node.js
    active versions: v16, v18, and, v20. Thanks to Ben Smyth for reporting this vulnerability and to Tobias
    Nieen for fixing it. (CVE-2023-30590)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nodejs.org/en/blog/vulnerability/june-2023-security-releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 16.20.1 / 18.16.1 / 20.3.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30589");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_win_installed.nbin", "macosx_nodejs_installed.nbin");
  script_require_keys("installed_sw/Node.js");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
var os = get_kb_item_or_exit('Host/OS');
if ('windows' >< tolower(os)) win_local = TRUE;
var app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '16.0.0', 'fixed_version' : '16.20.1' },
  { 'min_version' : '18.0.0', 'fixed_version' : '18.16.1' },
  { 'min_version' : '20.0.0', 'fixed_version' : '20.3.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
