#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2563-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146612);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2021-23840", "CVE-2021-23841");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DLA-2563-1 : openssl security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that there were two issues in the openssl
cryptographic system :

  - CVE-2021-23840: Prevent an issue where 'Digital
    EnVeloPe' EVP-related calls could cause applications to
    behave incorrectly or even crash.

  - CVE-2021-23841: Prevent an issue in the X509 certificate
    parsing caused by the lack of error handling while
    ingesting the 'issuer' field.

For Debian 9 'Stretch', these problems have been fixed in version
1.1.0l-1~deb9u3.

We recommend that you upgrade your openssl packages.

For the detailed security status of openssl please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/openssl

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openssl"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23840");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrypto1.1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl1.1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libcrypto1.1-udeb", reference:"1.1.0l-1~deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libssl-dev", reference:"1.1.0l-1~deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libssl-doc", reference:"1.1.0l-1~deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libssl1.1", reference:"1.1.0l-1~deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libssl1.1-udeb", reference:"1.1.0l-1~deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"openssl", reference:"1.1.0l-1~deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
