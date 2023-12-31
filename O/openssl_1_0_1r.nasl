#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(88529);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2015-3197", "CVE-2015-4000");
  script_bugtraq_id(74733);
  script_xref(name:"CERT", value:"257823");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"OpenSSL 1.0.1 < 1.0.1r Multiple Vulnerabilities (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSL 1.0.1 prior to 1.0.1r. It is, therefore, affected by the
following vulnerabilities :

  - A cipher algorithm downgrade vulnerability exists due to
    a flaw that is triggered when handling cipher
    negotiation. A remote attacker can exploit this to
    negotiate SSLv2 ciphers and complete SSLv2 handshakes
    even if all SSLv2 ciphers have been disabled on the
    server. Note that this vulnerability only exists if the
    SSL_OP_NO_SSLv2 option has not been disabled.
    (CVE-2015-3197)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160128.txt");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.1r or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4000");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.1r', min:"1.0.1", severity:SECURITY_WARNING);
