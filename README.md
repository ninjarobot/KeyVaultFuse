KeyVaultFuse
============

A file system for interacting with Azure Key Vault.

[![dotnet build and test](https://github.com/ninjarobot/KeyVaultFuse/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/ninjarobot/KeyVaultFuse/actions/workflows/build-and-test.yml)

This allows Linux applications to use the data in the key vault transparently, as if it were files on a the system. Typical usage would be to mount a key vault secret as a file to use for HTTPS settings when hosting a web server.

The file system supports listing the versions of objects as files as well. The versions can be sorted by date to enable techniques such as including the two most recent versions of a secret to enable rotation.

This uses `ls -t` to sort by time, `ls -1` so there is one line per file, and `ls -p` to include the path. This is piped to `grep -v /` to remove the entries with a slash since those are directories, and then `head -2` gets only the first 2 files (the newest two). This is piped to `xargs` which will execute `cat` once for each file, outputting this to a file named `newest_two_secrets`.

```
ls -t1p /path/to/secret | grep -v / | head -n | xargs cat > newest_two_secrets
```

Alternatively, the mount itself can be configured to concatenant versions so the resulting file contains multiple secrets by providing the mount option `concat_versions=2`.

Key Vault certificates store the private portion of the certificate as a secret of the same name. These list as ordinary files in the secrets directory. The public certificate can be retrieved as follows:

```
cat /kvfs/secrets/cert1/value | base64 -d |  openssl pkcs12 -clcerts -nokeys -passin pass:
Bag Attributes
    localKeyID: 01 00 00 00 
subject=CN = test.example
issuer=CN = test.example
-----BEGIN CERTIFICATE-----
MIIDNDCCAhygAwIBAgIQNgrD54vqRniooB8gGPHmajANBgkqhkiG9w0BAQsFADAX

[ SNIP ]

0P7b/RgCJcg=
-----END CERTIFICATE-----
```
and the private key can be similarly retrieved:
```
cat /kvfs/secrets/cert1/value | base64 -d | openssl pkcs12 -nocerts -nodes -passin pass:
Bag Attributes
    localKeyID: 01 00 00 00 
    friendlyName: e3388895-415d-4521-a59a-2a36ee8099ee
    Microsoft CSP Name: Microsoft Enhanced RSA and AES Cryptographic Provider
Key Attributes
    X509v3 Key Usage: 10 
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDuHWkWAXEcEgq6

[SNIP]

8gWVXTbHG01uwS7oU9O6/hPynQ==
-----END PRIVATE KEY-----
```

Usage
-----

This can be used by copying `KeyVaultFuse` into /usr/local/bin and then running standard `mount` commands:

```
mount -t fuse.KeyVaultFuse keyvault-name /path/to/keyvault -o allow_other
```

or adding to `/etc/fstab`:

```
keyvault-name /path/to/keyvault fuse.KeyVaultFuse allow_other 0 0
```

### Options

The default will mount the latest version of keys, certificates, and secrets. The values are cached for 5 minutes, and the filesystem will return an error if throttling limits are exceeded.

* Mount a single key, certificate, or secret - specify instead of key-vault name
   - keyvault-name/keys/key-name
   - keyvault-name/secrets/secret-name
   - keyvault-name/certificates/certificate-name
* Include versions - each key, secret, or certificate shows as a directory with versions underneath
   - option = include_versions
   - option = exclude_expired - when including versions, exclude those that are expired
   - option = exclude_disabled - when including versions, exclude those that are disabled
* Concatenate versions - each key, secret, or certificate will be concatenated to a file.
   - option = concat_versions=n - will concatenate up to n of the most recent versions
   - option = exclude_expired - when concatenating versions, exclude those that are expired
   - option = exclude_disabled - when concatenating versions, exclude those that are disabled
* Cache timeout - default is 300 seconds (5 minutes).
   - options = cache_timout_sec
   - options = cache_dir - only cache directory listings, not the secret values themselves.
   - options = disable_cache

By default, only the latest version of secret is returned, cache timeout is 5 minutes.

#### Caching

Since this appears as a local filesystem where reads are very cheap, many applications will perform heavy reads that could result in throttling or poor performance. This is impactful when using options such as `concat_versions` where multiple secrets are retrieved on a file read. To prevent performance issues, a caching layer is used so every read to the filesystem doesn't hit the key vault. This can be disabled by setting the `disable_cache` option. The cache is on a per-URI basis, so a single version of any given secret is cached for so many minutes.

Development
-----------

Prerequisites
```
apt install -y libfuse3-dev dotnet-sdk-9.0 clang lldb make
```
