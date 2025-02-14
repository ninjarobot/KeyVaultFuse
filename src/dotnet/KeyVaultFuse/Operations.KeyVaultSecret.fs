namespace KeyVaultFuse

open System
open System.Runtime.InteropServices
open FSharp.NativeInterop
open KeyVaultFuse
open Operations
open Libc
open Stat
open Fuse
open Azure.Security.KeyVault.Secrets

module KeyVaultSecretOperations =
    
    /// Sorts secrets by date in descending order.
    let sortedByDate (pages:seq<SecretProperties>) =
        query {
            for secretProps in pages do
            sortByDescending secretProps.CreatedOn.Value
            yield secretProps
        }

    /// Filter secrets that either don't set 'Enabled' or have 'Enabled' set to true.
    let filterDisabled (pages:seq<SecretProperties>) =
        query {
            for secretProps in pages do
            where (not(secretProps.Enabled.HasValue) || (secretProps.Enabled.HasValue && secretProps.Enabled.Value))
            yield secretProps
        }

    /// Filter secrets that either don't set 'ExpiresOn' or have 'ExpiresOn' set to a date in the future.
    let filterExpired (pages:seq<SecretProperties>) =
        query {
            for secretProps in pages do
            where (not(secretProps.ExpiresOn.HasValue) || secretProps.ExpiresOn.Value >= DateTimeOffset.Now)
            yield secretProps
        }

    /// Gets attributes for a secret list, version list, or secret version. 
    let secretsGetAttributes (secretClient:SecretClient) : GetAttributes =
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
            | [|"secrets"|] -> // Secrets directory
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFDIR ||| 0o0755)
                stat.st_nlink <- 2u
                stat.st_size <- 0L
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

    let secretsReadDir (secretClient:SecretClient) : ReadDirectory =
        fun path ->
            [
                "."
                ".."
                if path = "/" then
                    "secrets"
                    //"certificates"
                match path.Split('/', StringSplitOptions.RemoveEmptyEntries) with
                | [|"secrets"|] -> // Secrets directory
                    let secrets = secretClient.GetPropertiesOfSecrets()
                    yield! secrets |> Seq.map (fun s -> s.Name)
                | [|"secrets"; _|] -> // Single secret
                    "value"
                    "versions"
                | [|"secrets";secretName;"versions"|] -> // Secrets versions directory
                    let versions = secretClient.GetPropertiesOfSecretVersions(secretName)
                    // cannot retrieve disabled secrets, so exclude them
                    yield! versions |> filterDisabled |> Seq.map (fun v -> v.Version)
                | _ -> ()                    
            ]

    let secretsReadFile (secretClient:SecretClient) : ReadFile =
        fun path ->
            match path.Split('/', StringSplitOptions.RemoveEmptyEntries) with
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

    static let mutable secretClient:SecretClient = null

    static let secretsGetAttributesDelegateInstance = 
        Fuse.GetAttrDelegate(fun (path:string) statPtr fileInfoPtr ->
            let msg = String.Format("Getting attributes... at '{0}'", path)
            fuse_log(fuse_log_level.FUSE_LOG_INFO, msg)
            NativePtr.clear statPtr
            try
                match secretsGetAttributes secretClient path with
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
                secretsReadDir secretClient path
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
                let contentBytes = secretsReadFile secretClient path
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
    static let fuseOps = 
        fuse_operations(
            getattr = Marshal.GetFunctionPointerForDelegate<_>(secretsGetAttributesDelegateInstance),
            readdir = Marshal.GetFunctionPointerForDelegate<_>(secretsReadDirDelegateInstance),
            read = Marshal.GetFunctionPointerForDelegate<_>(secretsReadFileDelegateInstance),
            init = Marshal.GetFunctionPointerForDelegate<_>(initDelegateInstance)
        )

    static member SecretClient
        with set(value) = secretClient <- value

    static member FuseOps
        with get() = fuseOps

    /// Defining static members for FUSE operations to ensure they are not garbage collected.
    static member ReadDirDelegate = secretsReadDirDelegateInstance
    static member GetAttrDelegate = secretsGetAttributesDelegateInstance
    static member ReadDelegate = secretsReadFileDelegateInstance
