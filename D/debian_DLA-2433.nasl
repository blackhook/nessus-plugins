#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2433-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(142551);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/20");

  script_cve_id("CVE-2020-26939");

  script_name(english:"Debian DLA-2433-1 : bouncycastle security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that there was an issue in the bouncycastle crypto
library where attackers could obtain sensitive information due to
observable differences in its response to invalid input.

For Debian 9 'Stretch', this problem has been fixed in version
1.56-1+deb9u3.

We recommend that you upgrade your bouncycastle packages.

For the detailed security status of bouncycastle please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/bouncycastle

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/bouncycastle"
  );
  # https://security-tracker.debian.org/tracker/source-package/bouncycastle
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17470e37"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26939");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcmail-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcmail-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcpg-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcpg-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcpkix-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcpkix-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcprov-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcprov-java-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libbcmail-java", reference:"1.56-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libbcmail-java-doc", reference:"1.56-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libbcpg-java", reference:"1.56-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libbcpg-java-doc", reference:"1.56-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libbcpkix-java", reference:"1.56-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libbcpkix-java-doc", reference:"1.56-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libbcprov-java", reference:"1.56-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libbcprov-java-doc", reference:"1.56-1+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
