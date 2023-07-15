#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1932-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129362);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2019-1547", "CVE-2019-1563");

  script_name(english:"Debian DLA-1932-1 : openssl security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security vulnerabilities were found in OpenSSL, the Secure Sockets
Layer toolkit.

CVE-2019-1547

Normally in OpenSSL EC groups always have a co-factor present and this
is used in side channel resistant code paths. However, in some cases,
it is possible to construct a group using explicit parameters (instead
of using a named curve). In those cases it is possible that such a
group does not have the cofactor present. This can occur even where
all the parameters match a known named curve. If such a curve is used
then OpenSSL falls back to non-side channel resistant code paths which
may result in full key recovery during an ECDSA signature operation.
In order to be vulnerable an attacker would have to have the ability
to time the creation of a large number of signatures where explicit
parameters with no co-factor present are in use by an application
using libcrypto. For the avoidance of doubt libssl is not vulnerable
because explicit parameters are never used.

CVE-2019-1563

In situations where an attacker receives automated notification of the
success or failure of a decryption attempt an attacker, after sending
a very large number of messages to be decrypted, can recover a
CMS/PKCS7 transported encryption key or decrypt any RSA encrypted
message that was encrypted with the public RSA key, using a
Bleichenbacher padding oracle attack. Applications are not affected if
they use a certificate together with the private RSA key to the
CMS_decrypt or PKCS7_decrypt functions to select the correct recipient
info to decrypt.

For Debian 8 'Jessie', these problems have been fixed in version
1.0.1t-1+deb8u12.

We recommend that you upgrade your openssl packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openssl"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1563");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrypto1.0.0-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl1.0.0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"libcrypto1.0.0-udeb", reference:"1.0.1t-1+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libssl-dev", reference:"1.0.1t-1+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libssl-doc", reference:"1.0.1t-1+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libssl1.0.0", reference:"1.0.1t-1+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libssl1.0.0-dbg", reference:"1.0.1t-1+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"openssl", reference:"1.0.1t-1+deb8u12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
