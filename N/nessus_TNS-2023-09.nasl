#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172124);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2019-11358",
    "CVE-2020-7656",
    "CVE-2020-11023",
    "CVE-2020-28458",
    "CVE-2021-23445",
    "CVE-2022-4203",
    "CVE-2022-4304",
    "CVE-2022-4450",
    "CVE-2023-0215",
    "CVE-2023-0216",
    "CVE-2023-0217",
    "CVE-2023-0401"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Tenable Nessus <= 10.4.2 Multiple Vulnerabilities (TNS-2023-09)");

  script_set_attribute(attribute:"synopsis", value:
"Tenable Nessus running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application running on the remote host is 10.4.2 or 
earlier. It is, therefore, affected by multiple vulnerabilities in OpenSSL prior to version 3.0.8, spin.js prior 
to version 2.3.2, and datatables.net prior to version 1.13.2:
    
    - An attacker that had observed a genuine connection between a client and a server could use the flaw to send trial 
      messages to the server and record the time taken to process them. After a sufficiently large number of messages 
      the attacker could recover the pre-master secret used for the original connection. (CVE-2022-4304)

    - The function PEM_read_bio_ex() reads a PEM file from a BIO and parses and decodes any header data and the payload 
      data. Under certain conditions, a double free will occur. This will most likely lead to a crash. (CVE-2022-4450)

    - The public API function BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO. Under certain conditions, 
      the BIO chain is not properly cleaned up and the BIO passed by the caller still retains internal pointers to the previously 
      freed filter BIO. This will most likely result in a crash. (CVE-2023-0215)

    - An invalid pointer dereference on read can be triggered when an application tries to load malformed PKCS7 data. The result of the 
      dereference is an application crash which could lead to a denial of service attack. (CVE-2023-0216)

    - An invalid pointer dereference on read can be triggered when an application tries to check a malformed DSA public key by the 
      EVP_PKEY_public_check() function. This will most likely lead to an application crash. (CVE-2023-0217)

    - A NULL pointer can be dereferenced when signatures are being verified on PKCS7 signed or signedAndEnveloped data. In case the hash 
      algorithm used for the signature is known to the OpenSSL library but the implementation of the hash algorithm is not available the 
      digest initialization will fail. (CVE-2023-0401) 

    - A read buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking, which
      might result in a crash which could lead to a denial of service attack. (CVE-2022-4203)

    - All versions of package datatables.net are vulnerable to Prototype Pollution due to an incomplete fix for 
      https:/snyk.io/vuln/SNYK-JS-DATATABLESNET-598806. (CVE-2020-28458)

    - With the package datatables.net before 1.11.3 if an array is passed to the HTML escape entities function it would not 
      have its contents escaped. (CVE-2021-23445)

    - jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of 
      Object.prototype pollution. If an unsanitized source object contained an enumerable __proto__ property, it could extend the 
      native Object.prototype. (CVE-2019-11358)

    - In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing <option> elements from untrusted 
      sources, even after sanitizing it, to one of jQuery DOM manipulation methods may execute untrusted code. (CVE-2020-11023)

    - jquery prior to 1.9.0 allows Cross-site Scripting attacks via the load method that fails to recognize and remove <script> 
      HTML tags that contain a whitespace character and trigger execution of the enclosed script logic. (CVE-2020-7656)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-09");
  # https://docs.tenable.com/releasenotes/Content/nessus/nessus2023.htm#10.5.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8230254d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 10.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28458");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");
  script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include('vcf_extras.inc');

var app_info, constraints;

app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'max_version':'10.4.2', 'fixed_version':'10.5.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
