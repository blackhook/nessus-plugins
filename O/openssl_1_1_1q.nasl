##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162721);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/18");

  script_cve_id("CVE-2022-2097");
  script_xref(name:"IAVA", value:"2022-A-0265-S");

  script_name(english:"OpenSSL 1.1.1 < 1.1.1q Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.1.1q. It is, therefore, affected by a vulnerability as
referenced in the 1.1.1q advisory.

  - AES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt
    the entirety of the data under some circumstances. This could reveal sixteen bytes of data that was
    preexisting in the memory that wasn't written. In the special case of in place encryption, sixteen bytes
    of the plaintext would be revealed. Since OpenSSL does not support OCB based cipher suites for TLS and
    DTLS, they are both unaffected. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). Fixed in OpenSSL 1.1.1q
    (Affected 1.1.1-1.1.1p). (CVE-2022-2097)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cve.org/CVERecord?id=CVE-2022-2097");
  # https://github.com/openssl/openssl/commit/919925673d6c9cfed3c1085497f5dfbbed5fc431
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba4a37ba");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20220705.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.1q or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include('openssl_version.inc');

openssl_check_version(fixed:'1.1.1q', min:'1.1.1', severity:SECURITY_WARNING);
