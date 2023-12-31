#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(78553);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id("CVE-2014-3566", "CVE-2014-3567", "CVE-2014-3568");
  script_bugtraq_id(70574, 70585, 70586);
  script_xref(name:"CERT", value:"577193");

  script_name(english:"OpenSSL 1.0.0 < 1.0.1o Multiple Vulnerabilities (POODLE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server uses a version of
OpenSSL 1.0.0 prior to 1.0.0o. The OpenSSL library is, therefore,
affected by the following vulnerabilities :

  - An error exists related to the way SSL 3.0 handles
    padding bytes when decrypting messages encrypted using
    block ciphers in cipher block chaining (CBC) mode. A
    man-in-the-middle attacker can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections. This
    is also known as the 'POODLE' issue. (CVE-2014-3566)

  - An error exists related to session ticket handling that
    can allow denial of service attacks via memory leaks.
    (CVE-2014-3567)

  - An error exists related to the build configuration
    process and the 'no-ssl3' build option that allows
    servers and clients to process insecure SSL 3.0
    handshake messages. (CVE-2014-3568)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/openssl-1.0.0-notes.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20141015.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL 1.0.0o or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3568");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-3566");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.0o', min:"1.0.0", severity:SECURITY_WARNING);
