##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146374);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-1968");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"OpenSSL 1.0.2 < 1.0.2w Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is 1.0.2 prior to 1.0.2w. It is, therefore, affected by a
vulnerability as referenced in the 1.0.2w advisory. The Raccoon attack exploits a flaw in the TLS specification which
can lead to an attacker being able to compute the pre-master secret in connections which have used a Diffie-Hellman (DH)
based ciphersuite. In such a case this would result in the attacker being able to eavesdrop on all encrypted
communications sent over that TLS connection. The attack can only be exploited if an implementation re-uses a DH secret
across multiple TLS connections. Note that this issue only impacts DH ciphersuites and not ECDH ciphersuites.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20200909.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2w or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1968");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include('openssl_version.inc');

openssl_check_version(fixed:'1.0.2w', min:'1.0.2', severity:SECURITY_WARNING);

