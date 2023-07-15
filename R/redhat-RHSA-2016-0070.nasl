#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0070. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119442);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2013-2186",
    "CVE-2014-1869",
    "CVE-2014-3661",
    "CVE-2014-3662",
    "CVE-2014-3663",
    "CVE-2014-3664",
    "CVE-2014-3666",
    "CVE-2014-3667",
    "CVE-2014-3680",
    "CVE-2014-3681",
    "CVE-2015-1806",
    "CVE-2015-1807",
    "CVE-2015-1808",
    "CVE-2015-1810",
    "CVE-2015-1812",
    "CVE-2015-1813",
    "CVE-2015-1814",
    "CVE-2015-5317",
    "CVE-2015-5318",
    "CVE-2015-5319",
    "CVE-2015-5320",
    "CVE-2015-5321",
    "CVE-2015-5322",
    "CVE-2015-5323",
    "CVE-2015-5324",
    "CVE-2015-5325",
    "CVE-2015-5326",
    "CVE-2015-7537",
    "CVE-2015-7538",
    "CVE-2015-7539",
    "CVE-2015-8103",
    "CVE-2016-1905",
    "CVE-2016-1906"
  );
  script_xref(name:"RHSA", value:"2016:0070");
  script_xref(name:"TRA", value:"TRA-2016-23");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"RHEL 7 : openshift (RHSA-2016:0070)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Red Hat OpenShift Enterprise release 3.1.1 is now available with
updates to packages that fix several security issues, bugs and
introduce feature enhancements.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenShift Enterprise by Red Hat is the company's cloud computing
Platform-as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

The following security issues are addressed with this release :

An authorization flaw was discovered in Kubernetes; the API server did
not properly check user permissions when handling certain requests. An
authenticated remote attacker could use this flaw to gain additional
access to resources such as RAM and disk space. (CVE-2016-1905)

An authorization flaw was discovered in Kubernetes; the API server did
not properly check user permissions when handling certain build-
configuration strategies. A remote attacker could create build
configurations with strategies that violate policy. Although the
attacker could not launch the build themselves (launch fails when the
policy is violated), if the build configuration files were later
launched by other privileged services (such as automated triggers),
user privileges could be bypassed allowing attacker escalation.
(CVE-2016-1906)

An update for Jenkins Continuous Integration Server that addresses a
large number of security issues including XSS, CSRF, information
disclosure and code execution have been addressed as well.
(CVE-2013-2186, CVE-2014-1869, CVE-2014-3661, CVE-2014-3662
CVE-2014-3663, CVE-2014-3664, CVE-2014-3666, CVE-2014-3667
CVE-2014-3680, CVE-2014-3681, CVE-2015-1806, CVE-2015-1807
CVE-2015-1808, CVE-2015-1810, CVE-2015-1812, CVE-2015-1813
CVE-2015-1814, CVE-2015-5317, CVE-2015-5318, CVE-2015-5319
CVE-2015-5320, CVE-2015-5321, CVE-2015-5322, CVE-2015-5323
CVE-2015-5324, CVE-2015-5325, CVE-2015-5326 ,CVE-2015-7537
CVE-2015-7538, CVE-2015-7539, CVE-2015-8103)

Space precludes documenting all of the bug fixes and enhancements in
this advisory. See the OpenShift Enterprise 3.1 Release Notes, which
will be updated shortly for release 3.1.1, for details about these
changes :

https://docs.openshift.com/enterprise/3.1/release_notes/
ose_3_1_release_notes.html

All OpenShift Enterprise 3 users are advised to upgrade to these
updated packages.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:0070");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2186");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2014-1869");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2014-3661");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2014-3662");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2014-3663");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2014-3664");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2014-3666");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2014-3667");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2014-3680");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2014-3681");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-1806");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-1807");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-1808");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-1810");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-1812");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-1813");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-1814");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5317");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5318");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5319");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5320");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5321");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5322");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5323");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5324");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5325");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5326");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7537");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7538");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7539");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8103");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1905");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1906");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-23");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1906");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenNMS Java Object Unserialization Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-dockerregistry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-pod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-recycle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-sdn-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:heapster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-align-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ansi-green");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ansi-wrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-anymatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-arr-diff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-arr-flatten");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-array-unique");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-arrify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-async-each");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-binary-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-braces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-capture-stack-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-chokidar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-configstore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-create-error-class");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-deep-extend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-duplexer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-duplexify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-end-of-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-error-ex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-es6-promise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-event-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-expand-brackets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-expand-range");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-extglob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-filename-regex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-fill-range");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-for-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-for-own");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-from");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-glob-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-glob-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-got");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-graceful-fs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-binary-path");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-dotfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-equal-shallow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-extendable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-extglob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-glob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-npm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-number");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-plain-obj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-primitive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-redirect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-isobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-kind-of");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-latest-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lazy-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.assign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.baseassign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.basecopy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.bindcallback");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.createassigner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.defaults");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.getnative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.isarguments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.isarray");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.isiterateecall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.restparam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lowercase-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-map-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-micromatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-mkdirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-node-status-codes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-normalize-path");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-object-assign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-object.omit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-optimist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-os-homedir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-os-tmpdir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-osenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-package-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-parse-glob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-parse-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-pause-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-pinkie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-pinkie-promise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-prepend-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-preserve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ps-tree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-randomatic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-rc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-read-all-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-readdirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-regex-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-registry-url");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-repeat-element");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-semver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-semver-diff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-slide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-split");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-stream-combiner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-string-length");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-strip-json-comments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-success-symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-through");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-timed-out");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-touch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-undefsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-unzip-response");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-update-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-url-parse-lax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-uuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-write-file-atomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-xdg-basedir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss_wrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss_wrapper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-filter-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-lookup-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-playbooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-roles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:origin-kibana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tuned-profiles-atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0070";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_exists(rpm:"atomic-openshift-3.1", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-3.1.1.6-1.git.0.b57e8bd.el7aos")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-3.1", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-3.1.1.6-1.git.0.b57e8bd.el7aos")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-redistributable-3.1", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-redistributable-3.1.1.6-1.git.0.b57e8bd.el7aos")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-dockerregistry-3.1", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-dockerregistry-3.1.1.6-1.git.0.b57e8bd.el7aos")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-master-3.1", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-master-3.1.1.6-1.git.0.b57e8bd.el7aos")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-node-3.1", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-node-3.1.1.6-1.git.0.b57e8bd.el7aos")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-pod-3.1", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-pod-3.1.1.6-1.git.0.b57e8bd.el7aos")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-recycle-3.1", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-recycle-3.1.1.6-1.git.0.b57e8bd.el7aos")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-sdn-ovs-3.1", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-sdn-ovs-3.1.1.6-1.git.0.b57e8bd.el7aos")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-utils-3.0", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-utils-3.0.35-1.git.0.6a386dd.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"heapster-0.18.2-3.gitaf4752e.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jenkins-1.625.3-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-align-text-0.1.3-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ansi-green-0.1.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ansi-wrap-0.1.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-anymatch-1.3.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-arr-diff-2.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-arr-flatten-1.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-array-unique-0.2.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-arrify-1.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-async-each-1.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-binary-extensions-1.3.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-braces-1.8.2-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-capture-stack-trace-1.0.0-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-chokidar-1.4.1-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-configstore-1.4.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-create-error-class-2.0.1-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-deep-extend-0.3.2-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-duplexer-0.1.1-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-duplexify-3.4.2-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-end-of-stream-1.1.0-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-error-ex-1.2.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-es6-promise-3.0.2-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-event-stream-3.3.2-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-expand-brackets-0.1.4-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-expand-range-1.8.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-extglob-0.3.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-filename-regex-2.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-fill-range-2.2.3-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-for-in-0.1.4-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-for-own-0.1.3-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-from-0.1.3-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-glob-base-0.3.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-glob-parent-2.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-got-5.2.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-graceful-fs-4.1.2-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ini-1.1.0-6.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-binary-path-1.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-dotfile-1.0.2-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-equal-shallow-0.1.3-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-extendable-0.1.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-extglob-1.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-glob-2.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-npm-1.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-number-2.1.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-plain-obj-1.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-primitive-2.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-redirect-1.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-stream-1.0.1-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-isobject-2.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-kind-of-3.0.2-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-latest-version-2.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lazy-cache-1.0.2-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.assign-3.2.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.baseassign-3.2.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.basecopy-3.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.bindcallback-3.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.createassigner-3.1.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.defaults-3.1.2-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.getnative-3.9.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.isarguments-3.0.4-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.isarray-3.0.4-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.isiterateecall-3.0.9-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.keys-3.1.2-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.restparam-3.6.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lowercase-keys-1.0.0-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-map-stream-0.1.0-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-micromatch-2.3.5-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-mkdirp-0.5.0-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-node-status-codes-1.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-nodemon-1.8.1-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-normalize-path-2.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-object-assign-4.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-object.omit-2.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-optimist-0.4.0-5.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-os-homedir-1.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-os-tmpdir-1.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-osenv-0.1.0-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-package-json-2.3.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-parse-glob-3.0.4-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-parse-json-2.2.0-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-pause-stream-0.0.11-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-pinkie-2.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-pinkie-promise-2.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-prepend-http-1.0.1-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-preserve-0.2.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ps-tree-1.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-randomatic-1.1.5-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-rc-1.1.2-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-read-all-stream-3.0.1-3.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-readdirp-2.0.0-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-regex-cache-0.4.2-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-registry-url-3.0.3-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-repeat-element-1.1.2-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-semver-5.1.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-semver-diff-2.1.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-slide-1.1.5-3.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-split-0.3.3-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-stream-combiner-0.2.1-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-string-length-1.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-strip-json-comments-1.0.2-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-success-symbol-0.1.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-through-2.3.4-4.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-timed-out-2.0.0-3.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-touch-1.0.0-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-undefsafe-0.0.3-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-unzip-response-1.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-update-notifier-0.6.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-url-parse-lax-1.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-uuid-2.0.1-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-write-file-atomic-1.1.2-2.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-xdg-basedir-2.0.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss_wrapper-1.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss_wrapper-debuginfo-1.0.3-1.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-3.0", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-3.0.35-1.git.0.6a386dd.el7aos")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-docs-3.0", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-docs-3.0.35-1.git.0.6a386dd.el7aos")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-filter-plugins-3.0", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-filter-plugins-3.0.35-1.git.0.6a386dd.el7aos")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-lookup-plugins-3.0", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-lookup-plugins-3.0.35-1.git.0.6a386dd.el7aos")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-playbooks-3.0", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-playbooks-3.0.35-1.git.0.6a386dd.el7aos")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-roles-3.0", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-roles-3.0.35-1.git.0.6a386dd.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-2.4.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-debuginfo-2.4.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-devel-2.4.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"openvswitch-test-2.4.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"origin-kibana-0.5.0-1.el7aos")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-openvswitch-2.4.0-1.el7")) flag++;
  if (rpm_exists(rpm:"tuned-profiles-atomic-openshift-node-3.1", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tuned-profiles-atomic-openshift-node-3.1.1.6-1.git.0.b57e8bd.el7aos")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "atomic-openshift / atomic-openshift-clients / etc");
  }
}
