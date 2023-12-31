#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58565);
  script_version("1.11");
  script_cvs_date("Date: 2018/11/15 20:50:25");

  script_cve_id(
    "CVE-2006-7250",
    "CVE-2011-4619",
    "CVE-2012-0884",
    "CVE-2012-1165"
  );
  script_bugtraq_id(51281, 52181, 52428, 52764);

  script_name(english:"OpenSSL 1.0.0 < 1.0.0h Multiple Vulnerabilities");
  script_summary(english:"Does a banner check.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host may be affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running OpenSSL
version 1.0.0 prior to version 1.0.0h.  As such, it reportedly is
affected by the following vulnerabilities :

  - An error exists in the function 'mime_hdr_cmp' that
    could allow a NULL pointer to be dereferenced when
    parsing certain MIME headers. (CVE-2006-7250)

  - The fix for CVE-2011-4619 was not complete.

  - An error exists in the Cryptographic Message Syntax
    (CMS) and PKCS #7 implementation such that data can
    be decrypted using Million Message Attack (MMA)
    adaptive chosen cipher text attack. (CVE-2012-0884)

  - An error exists in the function 'mime_param_cmp' in the
    file 'crypto/asn1/asn_mime.c' that can allow a NULL
    pointer to be dereferenced when handling certain S/MIME
    content. (CVE-2012-1165)

Note that SSL/TLS applications are not necessarily affected, but those
using CMS, PKCS #7 and S/MIME decryption operations are."
  );
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=openssl-dev&amp;m=115685408414194&amp;w=2");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20120312.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/changelog.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2012/03/13/2");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2012/02/28/14");
   # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=dc95c53c6f3fc9007fea9376d02f7bd82d2a0fb4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82fc5c0b");
  script_set_attribute(attribute:"see_also", value:"https://rt.openssl.org/Ticket/Display.html?id=2711&user=guest&pass=guest");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 1.0.0h or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.0h', min:"1.0.0", severity:SECURITY_WARNING);
