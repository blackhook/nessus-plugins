#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1265-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106536);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id(
    "CVE-2013-1418",
    "CVE-2014-5351",
    "CVE-2014-5353",
    "CVE-2014-5355",
    "CVE-2016-3119",
    "CVE-2016-3120"
  );
  script_bugtraq_id(
    63555,
    70380,
    71679,
    74042
  );
  script_xref(name:"IAVB", value:"2016-B-0115-S");

  script_name(english:"Debian DLA-1265-1 : krb5 security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Kerberos, a system for authenticating users and services on a network,
was affected by several vulnerabilities. The Common Vulnerabilities
and Exposures project identifies the following issues.

CVE-2013-1418 Kerberos allows remote attackers to cause a denial of
service (NULL pointer dereference and daemon crash) via a crafted
request when multiple realms are configured.

CVE-2014-5351 Kerberos sends old keys in a response to a -randkey
-keepold request, which allows remote authenticated users to forge
tickets by leveraging administrative access.

CVE-2014-5353 When the KDC uses LDAP, allows remote authenticated
users to cause a denial of service (daemon crash) via a successful
LDAP query with no results, as demonstrated by using an incorrect
object type for a password policy.

CVE-2014-5355 Kerberos expects that a krb5_read_message data field is
represented as a string ending with a '\0' character, which allows
remote attackers to (1) cause a denial of service (NULL pointer
dereference) via a zero-byte version string or (2) cause a denial of
service (out-of-bounds read) by omitting the '\0' character,

CVE-2016-3119 Kerberos allows remote authenticated users to cause a
denial of service (NULL pointer dereference and daemon crash) via a
crafted request to modify a principal.

CVE-2016-3120 Kerberos allows remote authenticated users to cause a
denial of service (NULL pointer dereference and daemon crash) via an
S4U2Self request.

For Debian 7 'Wheezy', these problems have been fixed in version
1.10.1+dfsg-5+deb7u9.

We recommend that you upgrade your krb5 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00040.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/wheezy/krb5");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-gss-samples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkadm5clnt-mit8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkadm5srv-mit8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdb5-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");

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
if (deb_check(release:"7.0", prefix:"krb5-admin-server", reference:"1.10.1+dfsg-5+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-doc", reference:"1.10.1+dfsg-5+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-gss-samples", reference:"1.10.1+dfsg-5+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-kdc", reference:"1.10.1+dfsg-5+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-kdc-ldap", reference:"1.10.1+dfsg-5+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-locales", reference:"1.10.1+dfsg-5+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-multidev", reference:"1.10.1+dfsg-5+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-pkinit", reference:"1.10.1+dfsg-5+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-user", reference:"1.10.1+dfsg-5+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libkadm5clnt-mit8", reference:"1.10.1+dfsg-5+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libkadm5srv-mit8", reference:"1.10.1+dfsg-5+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libkdb5-6", reference:"1.10.1+dfsg-5+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libkrb5-dev", reference:"1.10.1+dfsg-5+deb7u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
