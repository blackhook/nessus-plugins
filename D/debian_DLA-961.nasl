#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-961-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100513);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-7650");

  script_name(english:"Debian DLA-961-1 : mosquitto security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2017-7650: Pattern based ACLs can be bypassed by clients that set
their username/client id to &lsquo;#&rsquo; or &lsquo;+&rsquo;. This
allows locally or remotely connected clients to access MQTT topics
that they do have the rights to. The same issue may be present in
third-party authentication/access control plugins for Mosquitto.

The vulnerability only comes into effect where pattern based ACLs are
in use, or potentially where third-party plugins are in use.

For Debian 7 'Wheezy', these problems have been fixed in version
0.15-2+deb7u1.

We recommend that you upgrade your mosquitto packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00034.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/mosquitto"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquitto0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquitto0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquittopp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquittopp0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-mosquitto");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libmosquitto0", reference:"0.15-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmosquitto0-dev", reference:"0.15-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmosquittopp0", reference:"0.15-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmosquittopp0-dev", reference:"0.15-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mosquitto", reference:"0.15-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mosquitto-clients", reference:"0.15-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-mosquitto", reference:"0.15-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
