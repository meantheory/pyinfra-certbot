import pyinfra_certbot as certbot

SUDO = True

certbot.provision()

# get tls certificates only
certbot.certonly(
    cert_name="example.com", domains="example.com,*.example.com", dns_provider="google"
)
