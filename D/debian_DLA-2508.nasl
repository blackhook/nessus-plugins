#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2508-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144627);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/26");

  script_cve_id("CVE-2020-35730");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/13");

  script_name(english:"Debian DLA-2508-1 : roundcube security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An issue was discovered in roundcube where in a cross-site scripting
(XSS) via HTML or plain text messages with malicious content was
possible.

For Debian 9 stretch, this problem has been fixed in version
1.2.3+dfsg.1-4+deb9u8.

We recommend that you upgrade your roundcube packages.

For the detailed security status of roundcube please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/roundcube

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/roundcube"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/roundcube"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35730");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-sqlite3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"roundcube", reference:"1.2.3+dfsg.1-4+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"roundcube-core", reference:"1.2.3+dfsg.1-4+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"roundcube-mysql", reference:"1.2.3+dfsg.1-4+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"roundcube-pgsql", reference:"1.2.3+dfsg.1-4+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"roundcube-plugins", reference:"1.2.3+dfsg.1-4+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"roundcube-sqlite3", reference:"1.2.3+dfsg.1-4+deb9u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
