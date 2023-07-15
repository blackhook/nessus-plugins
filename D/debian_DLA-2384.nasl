#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2384-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140810);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/30");

  script_cve_id("CVE-2020-24379", "CVE-2020-24916");

  script_name(english:"Debian DLA-2384-1 : yaws security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two issues have been found in yaws, a high performance HTTP 1.1
webserver written in Erlang.

CVE-2020-24379 Reject external resource requests in DAV in order to
avoid XML External Entity (XXE) attackes.

CVE-2020-24916 Sanitize CGI executable in order to avoid command
injection via CGI requests.

For Debian 9 stretch, these problems have been fixed in version
2.0.4+dfsg-1+deb9u1.

We recommend that you upgrade your yaws packages.

For the detailed security status of yaws please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/yaws

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/yaws"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/yaws"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-yapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-yaws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:yaws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:yaws-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:yaws-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:yaws-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:yaws-wiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:yaws-yapp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/28");
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
if (deb_check(release:"9.0", prefix:"erlang-yapp", reference:"2.0.4+dfsg-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-yaws", reference:"2.0.4+dfsg-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"yaws", reference:"2.0.4+dfsg-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"yaws-chat", reference:"2.0.4+dfsg-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"yaws-doc", reference:"2.0.4+dfsg-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"yaws-mail", reference:"2.0.4+dfsg-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"yaws-wiki", reference:"2.0.4+dfsg-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"yaws-yapp", reference:"2.0.4+dfsg-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
