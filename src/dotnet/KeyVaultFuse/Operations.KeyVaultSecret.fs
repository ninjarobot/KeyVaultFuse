(*
MIT License

Copyright (c) 2025 Dave Curylo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*)
namespace KeyVaultFuse

open System
open System.Runtime.InteropServices
open FSharp.NativeInterop
open KeyVaultFuse
open KeyVaultFuse.Fuse
open Operations
open Libc
open Stat
open Fuse
open Azure.Security.KeyVault.Secrets
open Azure.Security.KeyVault.Keys
open Azure.Security.KeyVault.Certificates

module KeyVaultSecretOperations =
    
    /// Sorts secrets by date in descending order.
    let sortedByDate (pages:seq<SecretProperties>) =
        query {
            for secretProps in pages do
            sortByDescending secretProps.CreatedOn.Value
            yield secretProps
        }

    /// Filter secrets that either don't set 'Enabled' or have 'Enabled' set to true.
    let filterDisabledCerts (pages:seq<CertificateProperties>) =
        query {
            for props in pages do
            where (not(props.Enabled.HasValue) || (props.Enabled.HasValue && props.Enabled.Value))
            yield props
        }

    let filterDisabledKeys (pages:seq<KeyProperties>) =
        query {
            for props in pages do
            where (not(props.Enabled.HasValue) || (props.Enabled.HasValue && props.Enabled.Value))
            yield props
        }

    let filterDisabledSecrets (pages:seq<SecretProperties>) =
        query {
            for props in pages do
            where (not(props.Enabled.HasValue) || (props.Enabled.HasValue && props.Enabled.Value))
            yield props
        }

    /// Filter secrets that either don't set 'ExpiresOn' or have 'ExpiresOn' set to a date in the future.
    let filterExpired (pages:seq<SecretProperties>) =
        query {
            for secretProps in pages do
            where (not(secretProps.ExpiresOn.HasValue) || secretProps.ExpiresOn.Value >= DateTimeOffset.Now)
            yield secretProps
        }

    let keyContents (key:KeyVaultKey) =
        if key.KeyType = KeyType.Rsa || key.KeyType = KeyType.RsaHsm then
            use rsa = key.Key.ToRSA()
            rsa.ExportSubjectPublicKeyInfoPem() |> System.Text.Encoding.UTF8.GetBytes
        else if key.KeyType = KeyType.Ec || key.KeyType = KeyType.EcHsm then
            use ec = key.Key.ToECDsa()
            ec.ExportSubjectPublicKeyInfoPem() |> System.Text.Encoding.UTF8.GetBytes
        else [||]
    
    /// Gets attributes for a secret list, version list, or secret version. 
    let secretsGetAttributes (certificateClient:CertificateClient, keyClient:KeyClient, secretClient:SecretClient) : GetAttributes =
        fun path ->
            let statBasicInfo() =
                let mutable stat = Stat()
                stat.st_uid <- getuid()
                stat.st_gid <- getgid()
                let now = DateTimeOffset.Now.ToUnixTimeSeconds()
                stat.st_atime <- now
                stat.st_atimensec <- uint64(now) * 1000000000UL
                stat.st_ctime <- now
                stat.st_ctimensec <- uint64(now) * 1000000000UL
                stat.st_mtime <- now
                stat.st_mtimensec <- uint64(now) * 1000000000UL
                stat
            match path.Split('/', StringSplitOptions.RemoveEmptyEntries) with
            | [||] -> // Root directory
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFDIR ||| 0o0755)
                stat.st_nlink <- 2u
                stat.st_size <- 0L
                stat |> Some
            | [|"certificates"|] // certificates directory
            | [|"keys"|] // keys directory
            | [|"secrets"|] -> // Secrets directory
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFDIR ||| 0o0755)
                stat.st_nlink <- 2u
                stat.st_size <- 0L
                stat |> Some
            | [|"certificates"; certName|] -> // Single certificate
                let cert = certificateClient.GetCertificate(certName)
                let contents = cert.Value.Cer
                let mutable stat = statBasicInfo()
                if(cert.Value.Properties.CreatedOn.HasValue) then
                    let unixTime = cert.Value.Properties.CreatedOn.Value.ToUnixTimeSeconds()
                    stat.st_ctime <- unixTime
                    stat.st_ctimensec <- uint64(unixTime) * 1000000000UL
                stat.st_mode <- uint32 (S_IFDIR ||| 0o0755)
                stat.st_nlink <- 1u
                stat.st_size <- contents.LongLength
                stat |> Some
            | [|"certificates";certName;"value"|] -> // Certificate value
                let cert = certificateClient.GetCertificate(certName)
                let contents = cert.Value.Cer
                let mutable stat = statBasicInfo()
                if(cert.Value.Properties.CreatedOn.HasValue) then
                    let unixTime = cert.Value.Properties.CreatedOn.Value.ToUnixTimeSeconds()
                    stat.st_ctime <- unixTime
                    stat.st_ctimensec <- uint64(unixTime) * 1000000000UL
                    stat.st_mtime <- unixTime
                    stat.st_mtimensec <- uint64(unixTime) * 1000000000UL
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFREG ||| 0o0444)
                stat.st_nlink <- 1u
                stat.st_size <- contents.LongLength
                stat |> Some
            | [|"certificates";certName;"versions"|] -> // Certificate versions directory
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFDIR ||| 0o0755)
                stat.st_nlink <- 1u
                stat.st_size <- 0L
                stat |> Some
            | [|"certificates";certName;"versions";version|] -> // Single certificate version
                let cert = certificateClient.GetCertificate(certName)
                let contents = cert.Value.Cer
                let mutable stat = statBasicInfo()
                if(cert.Value.Properties.CreatedOn.HasValue) then
                    let unixTime = cert.Value.Properties.CreatedOn.Value.ToUnixTimeSeconds()
                    stat.st_ctime <- unixTime
                    stat.st_ctimensec <- uint64(unixTime) * 1000000000UL
                    stat.st_mtime <- unixTime
                    stat.st_mtimensec <- uint64(unixTime) * 1000000000UL
                stat.st_mode <- uint32 (S_IFREG ||| 0o0444)
                stat.st_nlink <- 1u
                stat.st_size <- contents.LongLength
                stat |> Some
            | [|"keys"; keyName|] -> // Single key
                let key = keyClient.GetKey(keyName)
                let contents = key.Value |> keyContents
                let mutable stat = statBasicInfo()
                if(key.Value.Properties.CreatedOn.HasValue) then
                    let unixTime = key.Value.Properties.CreatedOn.Value.ToUnixTimeSeconds()
                    stat.st_ctime <- unixTime
                    stat.st_ctimensec <- uint64(unixTime) * 1000000000UL
                stat.st_mode <- uint32 (S_IFDIR ||| 0o0755)
                stat.st_nlink <- 1u
                stat.st_size <- contents.LongLength
                stat |> Some
            | [|"keys";keyName;"value"|] -> // Key value
                let key = keyClient.GetKey(keyName)
                let contents = key.Value |> keyContents
                let mutable stat = statBasicInfo()
                if(key.Value.Properties.CreatedOn.HasValue) then
                    let unixTime = key.Value.Properties.CreatedOn.Value.ToUnixTimeSeconds()
                    stat.st_ctime <- unixTime
                    stat.st_ctimensec <- uint64(unixTime) * 1000000000UL
                    stat.st_mtime <- unixTime
                    stat.st_mtimensec <- uint64(unixTime) * 1000000000UL
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFREG ||| 0o0444)
                stat.st_nlink <- 1u
                stat.st_size <- contents.LongLength
                stat |> Some
            | [|"keys";keyName;"versions"|] -> // Key versions directory
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFDIR ||| 0o0755)
                stat.st_nlink <- 1u
                stat.st_size <- 0L
                stat |> Some
            | [|"keys";keyName;"versions";version|] -> // Single key version
                let key = keyClient.GetKey(keyName)
                let contents = key.Value |> keyContents
                let mutable stat = statBasicInfo()
                if(key.Value.Properties.CreatedOn.HasValue) then
                    let unixTime = key.Value.Properties.CreatedOn.Value.ToUnixTimeSeconds()
                    stat.st_ctime <- unixTime
                    stat.st_ctimensec <- uint64(unixTime) * 1000000000UL
                    stat.st_mtime <- unixTime
                    stat.st_mtimensec <- uint64(unixTime) * 1000000000UL
                stat.st_mode <- uint32 (S_IFREG ||| 0o0444)
                stat.st_nlink <- 1u
                stat.st_size <- contents.LongLength
                stat |> Some
            | [|"secrets"; secretName|] -> // Single secret
                let secret = secretClient.GetSecret(secretName)
                let mutable stat = statBasicInfo()
                if(secret.Value.Properties.CreatedOn.HasValue) then
                    let unixTime = secret.Value.Properties.CreatedOn.Value.ToUnixTimeSeconds()
                    stat.st_ctime <- unixTime
                    stat.st_ctimensec <- uint64(unixTime) * 1000000000UL
                stat.st_mode <- uint32 (S_IFDIR ||| 0o0755)
                stat.st_nlink <- 1u
                stat.st_size <- System.Text.Encoding.UTF8.GetBytes(secret.Value.Value).LongLength
                stat |> Some
            | [|"secrets";secretName;"value"|] -> // Secrets versions directory
                let secret = secretClient.GetSecret(secretName)
                let mutable stat = statBasicInfo()
                if(secret.Value.Properties.CreatedOn.HasValue) then
                    let unixTime = secret.Value.Properties.CreatedOn.Value.ToUnixTimeSeconds()
                    stat.st_ctime <- unixTime
                    stat.st_ctimensec <- uint64(unixTime) * 1000000000UL
                    stat.st_mtime <- unixTime
                    stat.st_mtimensec <- uint64(unixTime) * 1000000000UL
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFREG ||| 0o0444)
                stat.st_nlink <- 1u
                stat.st_size <- System.Text.Encoding.UTF8.GetBytes(secret.Value.Value).LongLength
                stat |> Some
            | [|"secrets";secretName;"versions"|] -> // Secrets versions directory
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFDIR ||| 0o0755)
                stat.st_nlink <- 1u
                stat.st_size <- 0L
                stat |> Some
            | [|"secrets";secretName;"versions";version|] -> // Single secret version
                let secret = secretClient.GetSecret(secretName, version)
                let mutable stat = statBasicInfo()
                if(secret.Value.Properties.CreatedOn.HasValue) then
                    let unixTime = secret.Value.Properties.CreatedOn.Value.ToUnixTimeSeconds()
                    stat.st_ctime <- unixTime
                    stat.st_ctimensec <- uint64(unixTime) * 1000000000UL
                    stat.st_mtime <- unixTime
                    stat.st_mtimensec <- uint64(unixTime) * 1000000000UL
                stat.st_mode <- uint32 (S_IFREG ||| 0o0444)
                stat.st_nlink <- 1u
                stat.st_size <- System.Text.Encoding.UTF8.GetBytes(secret.Value.Value).LongLength
                stat |> Some
            | _ ->
                None

    let keyVaultReadDir (certificateClient:CertificateClient, keyClient:KeyClient, secretClient:SecretClient) : ReadDirectory =
        fun path ->
            [
                "."
                ".."
                if path = "/" then
                    "secrets"
                    "certificates"
                    "keys"
                match path.Split('/', StringSplitOptions.RemoveEmptyEntries) with
                | [|"certificates"|] -> // Secrets directory
                    let certs = certificateClient.GetPropertiesOfCertificates()
                    yield! certs |> Seq.map _.Name
                | [|"keys"|] -> // Secrets directory
                    let keys = keyClient.GetPropertiesOfKeys()
                    yield! keys |> Seq.map _.Name
                | [|"secrets"|] -> // Secrets directory
                    let secrets = secretClient.GetPropertiesOfSecrets()
                    yield! secrets |> Seq.map _.Name
                | [|"certificates"; _|] // Single certificate
                | [|"keys"; _|] // Single key
                | [|"secrets"; _|] -> // Single secret
                    "value"
                    "versions"
                | [|"certificates";certName;"versions"|] -> // Certificate versions directory
                    let versions = certificateClient.GetPropertiesOfCertificateVersions(certName)
                    yield! versions |> filterDisabledCerts |> Seq.map _.Version
                | [|"keys";keyName;"versions"|] -> // Key versions directory
                    let versions = keyClient.GetPropertiesOfKeyVersions (keyName)
                    yield! versions |> filterDisabledKeys |> Seq.map _.Version
                | [|"secrets";secretName;"versions"|] -> // Secret versions directory
                    let versions = secretClient.GetPropertiesOfSecretVersions(secretName)
                    // cannot retrieve disabled secrets, so exclude them
                    yield! versions |> filterDisabledSecrets |> Seq.map _.Version
                | _ -> ()                    
            ]

    let keyVaultReadFile (certificateClient:CertificateClient, keyClient:KeyClient, secretClient:SecretClient) : ReadFile =
        fun path ->
            match path.Split('/', StringSplitOptions.RemoveEmptyEntries) with
            | [|"certificates";certName;"value"|] ->
                let cert = certificateClient.GetCertificate(certName)
                cert.Value.Cer
            | [|"certificates";certName;"versions";version|] ->
                let cert = certificateClient.GetCertificateVersion(certName, version)
                cert.Value.Cer
            | [|"keys";keyName;"value"|] ->
                let key = keyClient.GetKey(keyName)
                key.Value |> keyContents
            | [|"keys";keyName;"versions";version|] ->
                let key = keyClient.GetKey(keyName,version)
                key.Value |> keyContents
            | [|"secrets";secretName;"value"|] ->
                let secret = secretClient.GetSecret(secretName)
                secret.Value.Value |> System.Text.Encoding.UTF8.GetBytes
            | [|"secrets";secretName;"versions";version|] ->
                let secret = secretClient.GetSecret(secretName, version)
                secret.Value.Value |> System.Text.Encoding.UTF8.GetBytes
            | _ ->
                [||]

open KeyVaultSecretOperations

/// Static delegates and structs for FUSE operations. Using a static instance ensures
/// there is a single instance that is not garbage collected.
type KeyVaultSecretFuse =

    static let mutable certificateClient:CertificateClient = null
    static let mutable keyClient:KeyClient = null
    static let mutable secretClient:SecretClient = null

    static let secretsGetAttributesDelegateInstance = 
        Fuse.GetAttrDelegate(fun (path:string) statPtr fileInfoPtr ->
            let msg = String.Format("Getting attributes... at '{0}'", path)
            fuse_log(fuse_log_level.FUSE_LOG_INFO, msg)
            NativePtr.clear statPtr
            try
                match secretsGetAttributes (certificateClient, keyClient, secretClient) path with
                | Some stat ->
                    stat |> NativePtr.write statPtr
                    0
                | None ->
                    -Errors.ENOENT
            with ex ->
                let msg = String.Format("Error getting attributes for '{0}': {1}", path, ex)
                fuse_log(fuse_log_level.FUSE_LOG_ERR, msg)
                -Errors.ENOENT
        )

    static let secretsReadDirDelegateInstance =
        ReadDirDelegate(fun path buffer fillerPtr offset fileInfo flags -> 
            let msg = String.Format("Reading directory at '{0}'", path)
            fuse_log(fuse_log_level.FUSE_LOG_INFO, msg)
            let filler = Marshal.GetDelegateForFunctionPointer<FuseFillDirDelegate>(fillerPtr)
            let FUSE_FILL_DIR_DEFAULTS = 0
            try
                keyVaultReadDir (certificateClient, keyClient, secretClient) path
                |> List.iter(fun file -> filler.Invoke(buffer, file, NativePtr.nullPtr<Stat>, 0L, FUSE_FILL_DIR_DEFAULTS) |> ignore)
                0
            with ex ->
                let msg = String.Format("Error reading directory '{0}': {1}", path, ex)
                fuse_log(fuse_log_level.FUSE_LOG_ERR, msg)
                -Errors.ENOENT
        )

    static let secretsReadFileDelegateInstance =
        ReadDelegate(fun path buffPtr size offset fi -> 
            System.Diagnostics.Debug.WriteLine("Reading from '{0}' size {1} offset {2}", path, size, offset)
            try
                let contentBytes = keyVaultReadFile (certificateClient, keyClient, secretClient) path
                let contentLength = contentBytes.LongLength
                let mutable size = size
                if contentLength > 0L then
                    let mutable length = 0L
                    length <- contentLength
                    if(offset < length) then
                        System.Diagnostics.Debug.WriteLine("offset ({0}) < length {1}", offset, length)
                        if(uint64 offset + size > uint64 length) then
                            size <- uint64 <| length - offset
                        Marshal.Copy(contentBytes, int(offset), buffPtr, int(size))
                    else // offset is beyond the length of the file
                        System.Diagnostics.Debug.WriteLine("offset ({0}) >= length {1}", offset, length)
                        size <- 0UL
                else
                    size <- 0UL
                int(size)
            with ex ->
                System.Console.Error.WriteLine("Error reading file '{0}': {1}", path, ex)
                -Errors.ENOENT
        )
    
    static let initDelegateInstance =
        InitDelegate(fun connPtr configPtr -> 
            let fuseConnInfo = NativePtr.read connPtr
            let mutable fuseConfig = NativePtr.read configPtr
            fuseConfig.kernel_cache <- 1
            fuseConfig |> NativePtr.write configPtr
        )

    static let openDelegateInstance =
        OpenDelegate(fun path _ ->
            fuse_log(fuse_log_level.FUSE_LOG_ERR, $"Open on Key Vault volume at path '{path}' not supported.")
            0
        )
    static let writeDelegateInstance =
        WriteDelegate(fun path _ _ _ _ ->
            fuse_log(fuse_log_level.FUSE_LOG_ERR, $"Write to Key Vault volume '{path}' not supported.")
            -Errors.EACCES)

    static let fuseOps = 
        fuse_operations(
            getattr = Marshal.GetFunctionPointerForDelegate<_>(secretsGetAttributesDelegateInstance),
            readdir = Marshal.GetFunctionPointerForDelegate<_>(secretsReadDirDelegateInstance),
            read = Marshal.GetFunctionPointerForDelegate<_>(secretsReadFileDelegateInstance),
            init = Marshal.GetFunctionPointerForDelegate<_>(initDelegateInstance),
            open' = Marshal.GetFunctionPointerForDelegate<_>(openDelegateInstance),
            write = Marshal.GetFunctionPointerForDelegate<_>(writeDelegateInstance)
        )

    static member CertificateClient
        with set(value) = certificateClient <- value

    static member KeyClient
        with set(value) = keyClient <- value

    static member SecretClient
        with set(value) = secretClient <- value

    static member FuseOps
        with get() = fuseOps

    /// Defining static members for FUSE operations to ensure they are not garbage collected.
    static member ReadDirDelegate = secretsReadDirDelegateInstance
    static member GetAttrDelegate = secretsGetAttributesDelegateInstance
    static member ReadDelegate = secretsReadFileDelegateInstance
    static member OpenDelegate = openDelegateInstance
    static member WriteDelegate = writeDelegateInstance
