#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2598-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(147902);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2020-25097");
  script_xref(name:"IAVB", value:"2021-B-0021");

  script_name(english:"Debian DLA-2598-1 : squid3 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Due to improper input validation, Squid is vulnerable to an HTTP
Request Smuggling attack.

This problem allows a trusted client to perform HTTP Request Smuggling
and access services otherwise forbidden by Squid security controls.

For Debian 9 stretch, this problem has been fixed in version
3.5.23-5+deb9u6.

We recommend that you upgrade your squid3 packages.

For the detailed security status of squid3 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/squid3

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/03/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/squid3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/squid3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25097");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-purge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squidclient");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"9.0", prefix:"squid", reference:"3.5.23-5+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"squid-cgi", reference:"3.5.23-5+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"squid-common", reference:"3.5.23-5+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"squid-dbg", reference:"3.5.23-5+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"squid-purge", reference:"3.5.23-5+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"squid3", reference:"3.5.23-5+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"squidclient", reference:"3.5.23-5+deb9u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
