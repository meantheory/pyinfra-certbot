import json
from pyinfra.api import FactBase, MaskString, QuoteString, operation, StringCommand
from pyinfra.api.deploy import deploy
from pyinfra.api.exceptions import DeployError
from pyinfra.api.util import get_arg_value, make_hash
from pyinfra.operations import apt, files, yum


class CertBot:
    def __init__(
        self, cert_name=None, domains=None, dns_provider=None,
    ):
        self._domains = domains
        self.dns_provider = dns_provider
        self.cert_name = cert_name

    def __call__(self, command):
        return self.command(command)

    @property
    def domains(self):
        return ",".join(self._domains)

    def command(self, command):
        bits = ["certbot", command]

        if self.cert_name:
            bits.append("--cert-name {0}".format(self.cert_name))

        if self.dns_provider:
            # create dns flag like, --dns-google
            bits.append("--dns-{0}".format(self.dns_provider))

        if self._domains:
            bits.append("-d {0}".format(self.domains))

        return StringCommand(*bits)


class CertBotFactBase(FactBase):
    abstract = True


class CertBotCertificates(CertBotFactBase):
    def command(self):
        cb = CertBot()
        return cb("certificates")

    def process(self, output):
        certificates = {}
        this = dict(name=None, fullchain=None, private=None)

        for line in output:
            try:
                rhs = line.split(":")[1].strip()
            except IndexError:
                continue

            if line.startswith("Certificate Name:"):
                this["name"] = rhs

            elif line.startswith("Certificate Path:"):
                this["fullchain"] = rhs

            elif line.startswith("Private Key Path:"):
                this["private"] = rhs

                certificates[this["name"]] = this
                this = dict(name=None, fullchain=None, private=None)

        return certificates


def _apt_install_certbot(state, host):

    # only tested in ubuntu 20.04, may need to add a repo for support elsewhere
    apt.packages(
        state, host, {"Install certbot via apt"}, "certbot", present=True,
    )


def _yum_install_certbot(state, host):
    raise NotImplemented("yum implementation needed. pull requests desired.")


def _install_certbot(state, host):
    if host.fact.deb_packages:
        _apt_install_certbot(state, host)
    elif host.fact.rpm_packages:
        _yum_install_certbot(state, host)
    else:
        raise DeployError(("no install method found", "can not install certbot"))


@deploy("deploy certbot")
def provision(state, host, config=None):
    _install_certbot(state, host)
    # TODO: configure host for existing letsencrypt account?


@operation
def certonly(state, host, cert_name, domains, dns_provider=None):

    current_certificates = host.fact.cert_bot_certificates()
    present = cert_name in current_certificates

    if not present:
        cb = CertBot(cert_name=cert_name, domains=domains, dns_provider=dns_provider,)

        yield cb("certonly")


@operation
def delete(state, host, cert_name):
    cb = CertBot(cert_name=cert_name,)

    yield cb("delete")
