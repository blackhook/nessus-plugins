##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:3172. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(130187);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2018-16470",
    "CVE-2018-1000632",
    "CVE-2019-3893",
    "CVE-2019-10198",
    "CVE-2019-14825"
  );
  script_bugtraq_id(
    106608,
    107166,
    107846,
    109151
  );
  script_xref(name:"RHSA", value:"2019:3172");

  script_name(english:"RHEL 7 : Red Hat Satellite 6 (RHSA-2019:3172)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2019:3172 advisory.

  - python-werkzeug: Cross-site scripting in render_full function in debug/tbtools.py (CVE-2016-10516)

  - python-jinja2: Sandbox escape due to information disclosure via str.format (CVE-2016-10745)

  - dom4j: XML Injection in Class: Element. Methods: addElement, addAttribute which can impact the integrity
    of XML documents (CVE-2018-1000632)

  - rubygem-rack: Buffer size in multipart parser allows for denial of service (CVE-2018-16470)

  - foreman: authorization bypasses in foreman-tasks leading to information disclosure (CVE-2019-10198)

  - python-jinja2: str.format_map allows sandbox escape (CVE-2019-10906)

  - python-twisted: Improper neutralization of CRLF characters in URIs and HTTP methods (CVE-2019-12387)

  - katello: registry credentials are captured in plain text during repository discovery (CVE-2019-14825)

  - foreman: Recover of plaintext password or token for the compute resources (CVE-2019-3893)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/79.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/88.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/113.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/138.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/287.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/319.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/400.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/732.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2016-10516");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2016-10745");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16470");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-1000632");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3893");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10198");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10906");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12387");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14825");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1512102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1620529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1646814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1696400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1698345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1698839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1719501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1729130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1739485");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000632");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 88, 113, 138, 287, 319, 400, 732);

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-runner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansiblerole-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansiblerole-insights-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-bootloaders-redhat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-bootloaders-redhat-tftpboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-discovery-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy-content");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-rackspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-telemetry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hfsplus-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-client-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kobo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmodulemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsolv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwebsockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:livecd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_xsendfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ostree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-mmvstatsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-admin-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-docker-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-docker-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-maintenance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-nodes-child");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-nodes-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-nodes-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-ostree-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-ostree-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-agent-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppetlabs-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppetserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pycairo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-blinker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-imgcreate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-kid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-mongoengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oauth2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-agent-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-client-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-docker-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-integrity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-oid_validation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-ostree-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-puppet-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-repoauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-rpm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-streamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-saslwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-semantic_version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-simplejson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-zope-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-amqp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-ansible-runner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-anyjson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-billiard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-celery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-click");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-crane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-flask");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-future");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-gobject-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-isodate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-itsdangerous");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-kombu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-lockfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-nectar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-okaara");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pexpect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-ptyprocess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pycurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-vine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-werkzeug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-linearstore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-router");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-access-insights-puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:repoview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhel8-kickstart-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bundler_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-clamp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-concurrent-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday_middleware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fast_gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hashie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-highline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-infoblox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-journald-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-journald-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo_parsers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo_wizards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-little-plugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-logging-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multipart-post");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-netrc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-powerbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-protection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rb-inotify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rkerberos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rubyipmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sinatra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dhcp_infoblox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dhcp_remote_isc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_discovery_image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dns_infoblox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dynflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_pulp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_remote_execution_ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:saslwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-capsule");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-debug-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-actioncable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-actionview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-activejob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-activestorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-arel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-coffee-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-coffee-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-coffee-script-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-concurrent-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-crass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-erubi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-execjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-globalid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-loofah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-marcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-method_source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mime-types-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mimemagic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mini_mime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mini_portile2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-mustermann");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-nio4r");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-rack-protection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-rack-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-rails-dom-testing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-rails-html-sanitizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-railties");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-sinatra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-sprockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-sprockets-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-thor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-thread_safe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-tilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-turbolinks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-tzinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-websocket-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-rubygem-websocket-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-ror52-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-activerecord-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-activerecord-session_store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-addressable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-algebrick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ancestry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-anemone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-angular-rails-templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-params");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-audited");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-awesome_print");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-bundler_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-clamp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-concurrent-ruby-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-css_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-deacon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-declarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-declarative-option");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-deep_cloneable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-deface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-diffy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-domain_name");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-dynflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ethon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-excon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-faraday");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fast_gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-google");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-kubevirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-rackspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-vsphere");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman-tasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman-tasks-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_ansible_core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_kubevirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_remote_execution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_remote_execution_core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_theme_satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_virt_who_configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-formatador");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-friendly_id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-get_process_mem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-gettext_i18n_rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-google-api-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-googleauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-graphql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-graphql-batch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_kubevirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_remote_execution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_tasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_virt_who_configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hashie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-highline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-http-cookie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-http-form_data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-http_parser.rb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ipaddress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-jgrep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-journald-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-journald-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-kubeclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ldap_fluff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-little-plugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-logging-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-memoist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-multipart-post");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-scp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ssh-krb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-netrc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-optimist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-os");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ovirt-engine-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ovirt_provision_plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-parse-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-polyglot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-powerbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-prometheus-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-promise.rb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-public_suffix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-qpid_messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-quantile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rabl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rack-cors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rack-jsonp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rails-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rainbow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rbovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rbvmomi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-record_tag_helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-recursive-open-struct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-redhat_access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-redhat_access_lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-representable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-responders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-retriable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-roadie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-roadie-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-robotex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ruby-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ruby2ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ruby_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-runcible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-safemode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-scoped_search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-secure_headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sequel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sexp_processor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-signet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_dynflow_core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sshkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-statsd-instrument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-typhoeus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-uber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unf_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unicode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unicode-display_width");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-validates_lengths_from_database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-webpack-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-wicked");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-will_paginate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-x-editable-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-zest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-runtime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Red Hat' >!< release) audit(AUDIT_OS_NOT, 'Red Hat');
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

repositories = {
    'satellite_6_6_el7': [
      'rhel-7-server-satellite-6.6-debug-rpms',
      'rhel-7-server-satellite-6.6-rpms',
      'rhel-7-server-satellite-6.6-source-rpms'
    ],
    'satellite_capsule_6_6_el7': [
      'rhel-7-server-satellite-capsule-6.6-debug-rpms',
      'rhel-7-server-satellite-capsule-6.6-rpms',
      'rhel-7-server-satellite-capsule-6.6-source-rpms'
    ]
};

found_repos = NULL;
host_repo_list = get_kb_list('Host/RedHat/repo-list/*');
if (!(empty_or_null(host_repo_list))) {
  found_repos = make_list();
  foreach repo_key (keys(repositories)) {
    foreach repo ( repositories[repo_key] ) {
      if (get_kb_item('Host/RedHat/repo-list/' + repo)) {
        append_element(var:found_repos, value:repo_key);
        break;
      }
    }
  }
  if(empty_or_null(found_repos)) audit(AUDIT_RHSA_NOT_AFFECTED, 'RHSA-2019:3172');
}

pkgs = [
    {'reference':'ansible-runner-1.3.4-2.el7ar', 'release':'7', 'el_string':'el7ar', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'ansiblerole-foreman_scap_client-0.0.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'ansiblerole-insights-client-1.6-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'candlepin-2.6.9-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'candlepin-selinux-2.6.9-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'createrepo_c-0.7.4-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'createrepo_c-libs-0.7.4-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-bootloaders-redhat-201901011200-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-bootloaders-redhat-tftpboot-201901011200-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-cli-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-debug-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-discovery-image-3.5.4-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-ec2-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-gce-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-installer-1.22.0.16-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-installer-katello-1.22.0.16-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-journald-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-libvirt-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-openstack-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-ovirt-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-postgresql-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-proxy-1.22.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-proxy-content-3.12.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-proxy-journald-1.22.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-rackspace-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-selinux-1.22.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-telemetry-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'foreman-vmware-1.22.0.32-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'hfsplus-tools-332.14-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'katello-3.12.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'katello-certs-tools-2.6.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'katello-client-bootstrap-1.7.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'katello-common-3.12.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'katello-debug-3.12.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'katello-selinux-3.1.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'katello-service-3.12.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'kobo-0.5.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'libmodulemd-1.7.0-1.pulp.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'libsolv-0.7.4-3.pulp.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'libwebsockets-2.4.2-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'livecd-tools-20.4-1.6.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'mod_passenger-4.0.18-24.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'mod_xsendfile-0.12-11.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'ostree-2017.1-2.atomic.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pcp-mmvstatsd-0.4-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-admin-client-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-docker-admin-extensions-3.2.3.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-docker-plugins-3.2.3.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-katello-1.0.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-maintenance-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-nodes-child-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-nodes-common-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-nodes-parent-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-ostree-admin-extensions-1.3.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-ostree-plugins-1.3.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-puppet-admin-extensions-2.19.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-puppet-plugins-2.19.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-puppet-tools-2.19.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-rpm-admin-extensions-2.19.1.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-rpm-plugins-2.19.1.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-selinux-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pulp-server-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'puppet-agent-5.5.12-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'puppet-agent-oauth-0.5.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'puppet-foreman_scap_client-0.3.19-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'puppetlabs-stdlib-4.25.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'puppetserver-5.3.8-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'pycairo-1.16.3-9.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-blinker-1.3-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-bson-3.2-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-gnupg-0.3.7-1.el7ui', 'release':'7', 'el_string':'el7ui', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-gofer-2.12.5-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-gofer-qpid-2.12.5-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-imgcreate-20.4-1.6.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-kid-0.9.6-11.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-mongoengine-0.10.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-oauth2-1.5.211-8.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-psutil-5.0.1-3.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pulp-agent-lib-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pulp-bindings-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pulp-client-lib-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pulp-common-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pulp-docker-common-3.2.3.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pulp-integrity-2.19.1.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pulp-oid_validation-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pulp-ostree-common-1.3.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pulp-puppet-common-2.19.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pulp-repoauth-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pulp-rpm-common-2.19.1.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pulp-streamer-2.19.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pymongo-3.2-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-pymongo-gridfs-3.2-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-qpid-1.35.0-5.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-qpid-proton-0.28.0-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-qpid-qmf-1.36.0-28.el7amq', 'cpu':'x86_64', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-saslwrapper-0.22-5.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-semantic_version-2.2.0-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-simplejson-3.2.0-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python-zope-interface-4.0.5-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-amqp-2.2.2-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-ansible-runner-1.3.4-2.el7ar', 'release':'7', 'el_string':'el7ar', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-anyjson-0.3.3-11.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-billiard-3.5.0.3-3.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-celery-4.0.2-9.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-click-6.7-9.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-crane-3.3.1-9.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-daemon-2.1.2-7.el7at', 'release':'7', 'el_string':'el7at', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-django-1.11.13-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-flask-0.12.2-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-future-0.16.0-11.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-gobject-3.28.3-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-gobject-base-3.28.3-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-isodate-0.5.4-12.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-itsdangerous-0.24-15.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-jinja2-2.10-10.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-kombu-4.0.2-13.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-lockfile-0.11.0-10.el7ar', 'release':'7', 'el_string':'el7ar', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-markupsafe-0.23-21.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-nectar-1.6.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-okaara-1.0.37-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-pexpect-4.6-1.el7at', 'release':'7', 'el_string':'el7at', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-ptyprocess-0.5.2-3.el7at', 'release':'7', 'el_string':'el7at', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-pycurl-7.43.0.2-4.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-solv-0.7.4-3.pulp.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-twisted-16.4.1-12.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-vine-1.1.3-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'python2-werkzeug-0.12.2-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'qpid-cpp-client-1.36.0-28.el7amq', 'cpu':'x86_64', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'qpid-cpp-client-devel-1.36.0-28.el7amq', 'cpu':'x86_64', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'qpid-cpp-server-1.36.0-28.el7amq', 'cpu':'x86_64', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'qpid-cpp-server-linearstore-1.36.0-28.el7amq', 'cpu':'x86_64', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'qpid-dispatch-router-1.5.0-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'qpid-dispatch-tools-1.5.0-4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'qpid-proton-c-0.28.0-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'qpid-qmf-1.36.0-28.el7amq', 'cpu':'x86_64', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'qpid-tools-1.36.0-28.el7amq', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'redhat-access-insights-puppet-1.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'repoview-0.6.6-11.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rhel8-kickstart-setup-0.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-ansi-1.4.3-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-bundler_ext-0.4.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-clamp-1.1.2-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-concurrent-ruby-1.1.4-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-facter-2.4.1-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-faraday-0.15.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-faraday_middleware-0.13.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-fast_gettext-1.1.0-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-ffi-1.4.0-3.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-foreman_scap_client-0.4.6-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-gssapi-1.1.2-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-hashie-2.0.5-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-highline-1.7.8-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-infoblox-3.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-journald-logger-2.0.4-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-journald-native-1.0.11-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-jwt-1.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-kafo-3.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-kafo_parsers-1.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-kafo_wizards-0.0.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-little-plugger-1.1.3-22.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-logging-2.2.2-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-logging-journald-2.0.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-mime-types-1.19-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-multi_json-1.12.2-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-multipart-post-2.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-net-ssh-4.2.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-netrc-0.7.7-9.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-newt-0.9.6-3.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-oauth-0.5.4-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-openscap-0.4.7-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-passenger-4.0.18-24.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-passenger-native-4.0.18-24.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-passenger-native-libs-4.0.18-24.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-powerbar-2.0.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-rack-1.6.4-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-rack-protection-1.5.3-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-rake-0.9.2.2-41.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-rb-inotify-0.9.7-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-rest-client-1.6.7-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-rkerberos-0.1.5-15.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-rsec-0.4.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-rubyipmi-0.10.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-sinatra-1.4.7-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-smart_proxy_ansible-3.0.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-smart_proxy_dhcp_infoblox-0.0.15-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-smart_proxy_dhcp_remote_isc-0.0.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-smart_proxy_discovery-1.0.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-smart_proxy_discovery_image-1.0.9-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-smart_proxy_dns_infoblox-1.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-smart_proxy_dynflow-0.2.2-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-smart_proxy_openscap-0.7.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-smart_proxy_pulp-1.4.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-smart_proxy_remote_execution_ssh-0.2.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'rubygem-tilt-1.3.7-2.git.0.3b416c9.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'saslwrapper-0.22-5.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'satellite-6.6.0-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'satellite-capsule-6.6.0-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'satellite-cli-6.6.0-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'satellite-common-6.6.0-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'satellite-debug-tools-6.6.0-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'satellite-installer-6.6.0.21-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-actioncable-5.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-actionmailer-5.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-actionpack-5.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-actionview-5.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-activejob-5.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-activemodel-5.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-activerecord-5.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-activestorage-5.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-activesupport-5.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-arel-9.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-builder-3.2.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-coffee-rails-4.2.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-coffee-script-2.4.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-coffee-script-source-1.12.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-concurrent-ruby-1.1.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-crass-1.0.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-erubi-1.7.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-execjs-2.7.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-globalid-0.4.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-i18n-1.4.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-loofah-2.2.2-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-mail-2.7.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-marcel-0.3.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-method_source-0.9.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-mime-types-3.2.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-mime-types-data-3.2018.0812-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-mimemagic-0.3.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-mini_mime-1.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-mini_portile2-2.3.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-multi_json-1.13.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-mustermann-1.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-nio4r-2.3.1-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-nokogiri-1.8.4-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-rack-2.0.6-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-rack-protection-2.0.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-rack-test-1.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-rails-5.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-rails-dom-testing-2.0.3-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-rails-html-sanitizer-1.0.4-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-railties-5.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-sinatra-2.0.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-sprockets-3.7.2-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-sprockets-rails-3.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-sqlite3-1.3.13-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-thor-0.20.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-thread_safe-0.3.6-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-tilt-2.0.8-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-turbolinks-2.5.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-tzinfo-1.2.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-websocket-driver-0.7.0-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-rubygem-websocket-extensions-0.1.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-ror52-runtime-1.0-4.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-activerecord-import-1.0.0-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-activerecord-session_store-1.1.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-addressable-2.6.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-algebrick-0.7.3-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-ancestry-3.0.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-anemone-0.7.2-20.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-angular-rails-templates-1.0.2-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-apipie-bindings-0.2.2-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-apipie-params-0.0.5-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-apipie-rails-0.5.14-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-audited-4.7.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-awesome_print-1.8.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-bundler_ext-0.4.1-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-clamp-1.1.2-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-concurrent-ruby-edge-0.4.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-css_parser-1.4.7-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-daemons-1.2.3-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-deacon-1.0.0-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-declarative-0.0.10-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-declarative-option-0.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-deep_cloneable-2.3.2-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-deface-1.3.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-diffy-3.0.1-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-domain_name-0.5.20160310-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-dynflow-1.2.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-ethon-0.12.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-excon-0.58.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-facter-2.4.0-6.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-faraday-0.15.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-fast_gettext-1.4.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-ffi-1.4.0-12.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-fog-aws-3.5.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-fog-core-2.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-fog-google-1.8.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-fog-json-1.2.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-fog-kubevirt-1.3.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-fog-libvirt-0.6.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-fog-openstack-1.0.8-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-fog-ovirt-1.1.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-fog-rackspace-0.1.4-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-fog-vsphere-3.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-fog-xml-0.1.2-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman-tasks-0.15.11.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman-tasks-core-0.3.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_ansible-3.0.7.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_ansible_core-3.0.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_bootdisk-15.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_discovery-15.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_docker-5.0.0.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_hooks-0.3.15-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_kubevirt-0.1.5.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_openscap-1.0.8-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_remote_execution-1.8.0.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_remote_execution_core-1.2.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_templates-6.0.3-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_theme_satellite-4.0.1.7-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-foreman_virt_who_configure-0.4.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-formatador-0.2.1-11.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-friendly_id-5.2.4-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-get_process_mem-0.2.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-gettext-3.1.4-10.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-gettext_i18n_rails-1.8.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-git-1.5.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-google-api-client-0.23.9-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-googleauth-0.6.7-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-graphql-1.8.14-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-graphql-batch-0.3.10-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-gssapi-1.2.0-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli-0.17.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_foreman-0.17.0.8-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_foreman_admin-0.0.8-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_foreman_ansible-0.3.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_foreman_bootdisk-0.1.3.3-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_foreman_discovery-1.0.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_foreman_docker-0.0.6.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_foreman_kubevirt-0.1.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_foreman_openscap-0.1.7-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_foreman_remote_execution-0.1.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_foreman_tasks-0.0.13-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_foreman_templates-0.1.2-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_foreman_virt_who_configure-0.0.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hammer_cli_katello-0.18.0.6-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-hashie-3.6.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-highline-1.7.8-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-http-3.3.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-http-cookie-1.0.2-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-http-form_data-2.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-http_parser.rb-0.6.0-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-httpclient-2.8.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-ipaddress-0.8.0-11.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-jgrep-1.3.3-12.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-journald-logger-2.0.4-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-journald-native-1.0.11-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-jwt-2.1.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-katello-3.12.0.27-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-kubeclient-4.3.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-ldap_fluff-0.4.7-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-little-plugger-1.1.3-24.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-locale-2.0.9-13.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-logging-2.2.2-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-logging-journald-2.0.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-memoist-0.16.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-multipart-post-2.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-net-ldap-0.15.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-net-ping-2.0.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-net-scp-1.2.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-net-ssh-4.2.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-net-ssh-krb-0.4.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-netrc-0.11.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-oauth-0.5.4-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-optimist-3.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-os-1.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-ovirt-engine-sdk-4.2.3-3.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-ovirt_provision_plugin-2.0.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-parse-cron-0.1.4-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-passenger-4.0.18-10.12.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-passenger-native-4.0.18-10.12.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-passenger-native-libs-4.0.18-10.12.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-pg-0.21.0-3.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-polyglot-0.3.5-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-powerbar-2.0.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-prometheus-client-0.7.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-promise.rb-0.7.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-public_suffix-3.0.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-qpid_messaging-1.36.0-9.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-quantile-0.2.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-rabl-0.13.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-rack-cors-1.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-rack-jsonp-1.3.1-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-rails-i18n-5.1.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-rainbow-2.2.1-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-rbovirt-0.1.7-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-rbvmomi-2.2.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-record_tag_helper-1.0.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-recursive-open-struct-1.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-redhat_access-2.2.8-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-redhat_access_lib-1.1.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-representable-3.0.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-responders-2.4.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-rest-client-2.0.1-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-retriable-3.1.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-roadie-3.4.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-roadie-rails-2.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-robotex-1.0.0-21.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-ruby-libvirt-0.7.0-4.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-ruby2ruby-2.4.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-ruby_parser-3.10.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-runcible-2.11.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-safemode-1.3.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-scoped_search-4.1.7-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-secure_headers-6.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-sequel-5.7.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-sexp_processor-4.10.0-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-signet-0.11.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-smart_proxy_dynflow_core-0.2.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-sshkey-1.9.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-statsd-instrument-2.1.4-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-text-1.3.0-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-typhoeus-1.3.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-uber-0.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-unf-0.1.3-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-unf_ext-0.0.6-9.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-unicode-0.4.4.1-6.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-unicode-display_width-1.0.5-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-validates_lengths_from_database-0.5.0-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-webpack-rails-0.9.8-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-wicked-1.3.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-will_paginate-3.1.5-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-x-editable-rails-1.5.5-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-rubygem-zest-0.0.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']},
    {'reference':'tfm-runtime-5.0-7.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'repo_list':['satellite_6_6_el7', 'satellite_capsule_6_6_el7']}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  repo_list = NULL;
  if (!empty_or_null(package_array['repo_list'])) repo_list = package_array['repo_list'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'RHEL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    repocheck = FALSE;
    if (empty_or_null(found_repos))
    {
      repocheck = TRUE;
    }
    else
    {
      foreach repo (repo_list) {
        if (contains_element(var:found_repos, value:repo))
        {
          repocheck = TRUE;
          break;
        }
      }
    }
    if (repocheck && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  if (empty_or_null(host_repo_list)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible-runner / ansiblerole-foreman_scap_client / etc');
}
