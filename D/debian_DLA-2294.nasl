#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2294-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139094);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/03");

  script_cve_id("CVE-2018-15750", "CVE-2018-15751");

  script_name(english:"Debian DLA-2294-1 : salt security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two issues have been found in salt, a remote manager to administer
servers.

These issues are related to remote hackers bypassing authentication to
execute arbitrary commands and getting informations about files on the
server

For Debian 9 stretch, these problems have been fixed in version
2016.11.2+ds-1+deb9u5.

We recommend that you upgrade your salt packages.

For the detailed security status of salt please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/salt

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/salt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/salt"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-syndic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");
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
if (deb_check(release:"9.0", prefix:"salt-api", reference:"2016.11.2+ds-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"salt-cloud", reference:"2016.11.2+ds-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"salt-common", reference:"2016.11.2+ds-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"salt-doc", reference:"2016.11.2+ds-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"salt-master", reference:"2016.11.2+ds-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"salt-minion", reference:"2016.11.2+ds-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"salt-proxy", reference:"2016.11.2+ds-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"salt-ssh", reference:"2016.11.2+ds-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"salt-syndic", reference:"2016.11.2+ds-1+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
