#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-8cbe2a05cd.
#

include("compat.inc");

if (description)
{
  script_id(122285);
  script_version("1.4");
  script_cvs_date("Date: 2020/02/12");

  script_cve_id("CVE-2018-12546", "CVE-2018-12550", "CVE-2018-12551");
  script_xref(name:"FEDORA", value:"2019-8cbe2a05cd");

  script_name(english:"Fedora 28 : mosquitto (2019-8cbe2a05cd)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes for the following CVES :

  - CVE-2018-12546

  - CVE-2018-12550

  - CVE-2018-12551 

The list of other fixes addressed in version 1.5.6 is: Broker :

  - Fixed comment handling for config options that have
    optional arguments.

  - Improved documentation around bridge topic remapping.

  - Handle mismatched handshakes (e.g. QoS1 PUBLISH with
    QoS2 reply) properly.

  - Fix spaces not being allowed in the bridge
    remote_username option. Closes #1131.

  - Allow broker to always restart on Windows when using
    log_dest file. Closes #1080.

  - Fix Will not being sent for Websockets clients. Closes
    #1143.

  - Windows: Fix possible crash when client disconnects.
    Closes #1137.

  - Fixed durable clients being unable to receive messages
    when offline, when per_listener_settings was set to
    true. Closes #1081.

  - Add log message for the case where a client is
    disconnected for sending a topic with invalid UTF-8.
    Closes #1144.

Library :

  - Fix TLS connections not working over SOCKS.

  - Don't clear SSL context when TLS connection is closed,
    meaning if a user provided an external SSL_CTX they have
    less chance of leaking references.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-8cbe2a05cd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mosquitto package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mosquitto");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"mosquitto-1.5.6-1.fc28")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mosquitto");
}
