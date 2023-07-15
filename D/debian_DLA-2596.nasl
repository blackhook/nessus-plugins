#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2596-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(147813);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/23");

  script_cve_id("CVE-2017-12424", "CVE-2017-20002");

  script_name(english:"Debian DLA-2596-1 : shadow security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in the shadow suite of login
tools. An attacker may escalate privileges in specific configurations.

CVE-2017-20002

Shadow incorrectly lists pts/0 and pts/1 as physical terminals in
/etc/securetty. This allows local users to login as password-less
users even if they are connected by non-physical means such as SSH
(hence bypassing PAM's nullok_secure configuration). This notably
affects environments such as virtual machines automatically generated
with a default blank root password, allowing all local users to
escalate privileges. It should be noted however that /etc/securetty
will be dropped in Debian 11/bullseye.

CVE-2017-12424

The newusers tool could be made to manipulate internal data structures
in ways unintended by the authors. Malformed input may lead to crashes
(with a buffer overflow or other memory corruption) or other
unspecified behaviors. This crosses a privilege boundary in, for
example, certain web-hosting environments in which a Control Panel
allows an unprivileged user account to create subaccounts.

For Debian 9 stretch, these problems have been fixed in version
1:4.4-4.1+deb9u1.

We recommend that you upgrade your shadow packages.

For the detailed security status of shadow please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/shadow

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/shadow"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/shadow"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected login, passwd, and uidmap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12424");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:login");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:passwd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uidmap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"login", reference:"1:4.4-4.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"passwd", reference:"1:4.4-4.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"uidmap", reference:"1:4.4-4.1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
