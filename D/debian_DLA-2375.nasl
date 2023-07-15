#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2375-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140665);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_cve_id("CVE-2019-20917", "CVE-2020-25269");

  script_name(english:"Debian DLA-2375-1 : inspircd security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two security issues were discovered in the modules of the InspIRCd IRC
daemon, which could result in denial of service.

CVE-2019-20917

mysql module before v3.3.0 contains a NULL pointer dereference when
built against mariadb-connector-c. When combined with the sqlauth or
sqloper modules this vulnerability can be used to remotely crash an
InspIRCd server by any user able to connect to a server.

CVE-2020-25269

The pgsql module contains a use after free vulnerability. When
combined with the sqlauth or sqloper modules this vulnerability can be
used to remotely crash an InspIRCd server by any user able to connect
to a server.

For Debian 9 stretch, these problems have been fixed in version
2.0.23-2+deb9u1.

We recommend that you upgrade your inspircd packages.

For the detailed security status of inspircd please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/inspircd

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/inspircd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/inspircd"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inspircd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inspircd-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inspircd-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/21");
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
if (deb_check(release:"9.0", prefix:"inspircd", reference:"2.0.23-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"inspircd-dbg", reference:"2.0.23-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"inspircd-dev", reference:"2.0.23-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
