#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128116);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/12");

  script_cve_id(
    "CVE-2019-1547",
    "CVE-2019-1549",
    "CVE-2019-1552",
    "CVE-2019-1563"
  );
  script_xref(name:"IAVA", value:"2019-A-0303-S");

  script_name(english:"OpenSSL 1.1.1 < 1.1.1d Multiple Vulnerabilities");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior
to tested version. It is, therefore, affected by the following
vulnerabilities :

  - Normally in OpenSSL EC groups always have a co-factor
    present and this is used in side channel resistant code
    paths. However, in some cases, it is possible to
    construct a group using explicit parameters (instead of
    using a named curve). In those cases it is possible
    that such a group does not have the cofactor present.
    This can occur even where all the parameters match a
    known named curve. If such a curve is used then
    OpenSSL falls back to non-side channel resistant code
    paths which may result in full key recovery during an
    ECDSA signature operation. In order to be vulnerable an
    attacker would have to have the ability to time the
    creation of a large number of signatures where explicit
    parameters with no co-factor present are in use by an
    application using libcrypto. For the avoidance of doubt
    libssl is not vulnerable because explicit parameters are
    never used. OpenSSL versions 1.1.1, 1.1.0 and 1.0.2 are
    affected by this issue. (CVE-2019-1547)

  - OpenSSL 1.1.1 introduced a rewritten random number
    generator (RNG). This was intended to include protection
    in the event of a fork() system call in order to ensure
    that the parent and child processes did not share the
    same RNG state. However this protection was not being
    used in the default case. A partial mitigation for this
    issue is that the output from a high precision timer is
    mixed into the RNG state so the likelihood of a parent
    and child process sharing state is significantly
    reduced. If an application already calls
    OPENSSL_init_crypto() explicitly using
    OPENSSL_INIT_ATFORK then this problem does not occur at
    all. OpenSSL version 1.1.1 is affected by this issue.
    (CVE-2019-1549)

  - In situations where an attacker receives automated
    notification of the success or failure of a decryption
    attempt an attacker, after sending a very large number
    of messages to be decrypted, can recover a CMS/PKCS7
    transported encryption key or decrypt any RSA encrypted
    message that was encrypted with the public RSA key,
    using a Bleichenbacher padding oracle attack.
    Applications are not affected if they use a certificate
    together with the private RSA key to the CMS_decrypt or
    PKCS7_decrypt functions to select the correct recipient
    info to decrypt. (CVE-2019-1563)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://github.com/openssl/openssl/commit/54aa9d51b09d67e90db443f682cface795f5af9e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c46dca59");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20190910.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20190730.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.1d or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1549");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:"1.1.1d", min:"1.1.1", severity:SECURITY_WARNING);
